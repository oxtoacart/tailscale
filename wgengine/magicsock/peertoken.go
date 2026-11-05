// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"net/netip"
	"time"

	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/rate"
	"tailscale.com/types/key"
	"tailscale.com/util/clientmetric"
)

// PeerTokenMessage is a [disco.PeerToken] message received by a [Conn],
// along with the authenticated transport-level facts about its sender.
//
// Receiving a PeerTokenMessage means only that the message was sealed by the
// holder of DiscoKey's private key; the token itself is unverified.
type PeerTokenMessage struct {
	// Token is the compact serialized JWT from the message.
	Token string

	// DiscoKey is the disco public key that sealed the message. The
	// message's authenticity under this key has been verified.
	DiscoKey key.DiscoPublic

	// DERPNodeKey is the node key from which the message was received at
	// the DERP layer, which DERP authenticates. It is zero if the message
	// arrived over UDP.
	DERPNodeKey key.NodePublic

	// DERPRegion is the DERP region via which the message was received, or
	// zero if it arrived over UDP.
	DERPRegion int

	// UDPSrc is the UDP source address of the message, or the zero value if
	// it arrived over DERP.
	UDPSrc netip.AddrPort
}

// Peer token messages are accepted from senders that aren't in the netmap,
// which requires a Curve25519 computation per message before we know
// whether it's legitimate. Rate limit them so that unauthenticated senders
// can't burn our CPU. Legitimate peers send tokens rarely (on first contact
// and on renewal).
const (
	peerTokenRate  = 20 // messages per second
	peerTokenBurst = 50
)

var (
	metricRecvDiscoPeerToken            = clientmetric.NewCounter("magicsock_disco_recv_peer_token")
	metricRecvDiscoPeerTokenUnknownPeer = clientmetric.NewCounter("magicsock_disco_recv_peer_token_unknown_peer")
	metricRecvDiscoPeerTokenRateLimited = clientmetric.NewCounter("magicsock_disco_recv_peer_token_rate_limited")
)

// SetPeerTokenHandler sets the function that is called (in its own
// goroutine) for each [disco.PeerToken] message received, including from
// senders whose disco key is not known from the netmap. If fn is nil, peer
// token messages are ignored and disco messages from unknown senders are
// dropped without being opened.
func (c *Conn) SetPeerTokenHandler(fn func(PeerTokenMessage)) {
	c.peerTokenHandler.Store(fn)
}

// allowPeerTokenLocked reports whether a peer token message may be
// processed now, under the rate limit. c.mu must be held.
func (c *Conn) allowPeerTokenLocked() bool {
	if c.peerTokenLimiter == nil {
		c.peerTokenLimiter = rate.NewLimiter(rate.Every(time.Second/peerTokenRate), peerTokenBurst)
	}
	if !c.peerTokenLimiter.Allow() {
		metricRecvDiscoPeerTokenRateLimited.Add(1)
		return false
	}
	return true
}

// handleUnknownSenderDiscoLocked handles a disco message, msg, from sender,
// a disco key not associated with any known peer. Only [disco.PeerToken]
// messages are accepted from unknown senders; anything else is dropped.
//
// It reports whether msg was a peer token message that was passed to the
// handler. c.mu must be held.
func (c *Conn) handleUnknownSenderDiscoLocked(msg []byte, sender key.DiscoPublic, src epAddr, derpNodeSrc key.NodePublic) bool {
	fn := c.peerTokenHandler.Load()
	if fn == nil || src.vni.IsSet() {
		return false
	}
	if !c.allowPeerTokenLocked() {
		return false
	}
	// Deliberately don't cache this shared key in c.discoInfo: the sender
	// is unauthenticated, and caching would let anyone grow that map.
	shared := c.discoAtomic.Private().Shared(sender)
	payload, ok := shared.Open(msg[discoHeaderLen:])
	if !ok {
		metricRecvDiscoBadKey.Add(1)
		return false
	}
	dm, err := disco.Parse(payload)
	if err != nil {
		metricRecvDiscoBadParse.Add(1)
		return false
	}
	pt, ok := dm.(*disco.PeerToken)
	if !ok {
		return false
	}
	if cb := c.captureHook.Load(); cb != nil {
		cb(packet.PathDisco, time.Now(), disco.ToPCAPFrame(src.ap, derpNodeSrc, payload), packet.CaptureMeta{})
	}
	metricRecvDiscoPeerTokenUnknownPeer.Add(1)
	c.dispatchPeerTokenLocked(fn, pt, sender, src, derpNodeSrc)
	return true
}

// dispatchPeerTokenLocked hands pt to fn in a new goroutine. The handler
// typically reconfigures peers (calling back into c), so it must not run
// with c.mu held. c.mu must be held.
func (c *Conn) dispatchPeerTokenLocked(fn func(PeerTokenMessage), pt *disco.PeerToken, sender key.DiscoPublic, src epAddr, derpNodeSrc key.NodePublic) {
	metricRecvDiscoPeerToken.Add(1)
	m := PeerTokenMessage{
		Token:    string(pt.Token),
		DiscoKey: sender,
	}
	if src.ap.Addr() == tailcfg.DerpMagicIPAddr {
		m.DERPNodeKey = derpNodeSrc
		m.DERPRegion = int(src.ap.Port())
	} else {
		m.UDPSrc = src.ap
	}
	go fn(m)
}

// SendPeerToken sends token, a control-signed peer token, to the peer with
// node key dst in a [disco.PeerToken] message, over DERP and, if one is
// known, the peer's best direct path. The peer must be known to c.
func (c *Conn) SendPeerToken(dst key.NodePublic, token []byte) error {
	if len(token) == 0 || len(token) > disco.MaxPeerTokenLen {
		return errors.New("invalid peer token length")
	}
	c.mu.Lock()
	ep, ok := c.peerMap.endpointForNodeKey(dst)
	c.mu.Unlock()
	if !ok {
		return errors.New("unknown peer")
	}
	epDisco := ep.disco.Load()
	if epDisco == nil {
		return errors.New("peer has no disco key")
	}
	ep.mu.Lock()
	derpAddr := ep.derpAddr
	best := ep.bestAddr.epAddr
	ep.mu.Unlock()

	m := &disco.PeerToken{Token: token}
	var sentAny bool
	var firstErr error
	for _, dstAddr := range []epAddr{{ap: derpAddr}, best} {
		if !dstAddr.ap.IsValid() {
			continue
		}
		sent, err := c.sendDiscoMessage(dstAddr, dst, epDisco.key(), m, discoVerboseLog)
		sentAny = sentAny || sent
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if sentAny {
		return nil
	}
	if firstErr != nil {
		return firstErr
	}
	return errors.New("no path to peer")
}
