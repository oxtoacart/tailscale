// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"errors"
	"net/netip"
	"time"

	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tstime/mono"
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
	metricSentDiscoPeerToken            = clientmetric.NewCounter("magicsock_disco_sent_peer_token")
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
//
// Callers don't normally need this: c automatically presents the self
// node's own token (from its [nodecap.PeerToken] capability) to the peers it
// contacts.
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
	return c.sendPeerToken(dst, epDisco.key(), token, derpAddr, best)
}

// PresentPeerToken presents our own peer token, if we have one, to the peer
// with node key dst now, rather than waiting until we next start disco
// pings to it, unless we already presented it recently, as
// [Conn.SendPeerToken] would before a disco ping. It's a no-op if dst isn't
// a known peer.
//
// LocalBackend calls it for a peer it didn't have that presents its token,
// which may need ours to accept traffic from us.
func (c *Conn) PresentPeerToken(dst key.NodePublic) {
	c.mu.Lock()
	ep, ok := c.peerMap.endpointForNodeKey(dst)
	c.mu.Unlock()
	if !ok {
		return
	}
	epDisco := ep.disco.Load()
	if epDisco == nil {
		return
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.maybeSendPeerTokenLocked(mono.Now(), epDisco)
}

// sendPeerToken sends token to the peer with node key dst and disco key
// dstDisco, via derpAddr and best, each if valid.
//
// Recipients ignore tokens arriving via a UDP relay server, so best isn't
// used if it's a relay path.
func (c *Conn) sendPeerToken(dst key.NodePublic, dstDisco key.DiscoPublic, token []byte, derpAddr netip.AddrPort, best epAddr) error {
	if best.vni.IsSet() {
		best = epAddr{}
	}
	m := &disco.PeerToken{Token: token}
	var sentAny bool
	var firstErr error
	for _, dstAddr := range []epAddr{{ap: derpAddr}, best} {
		if !dstAddr.ap.IsValid() {
			continue
		}
		sent, err := c.sendDiscoMessage(dstAddr, dst, dstDisco, m, discoVerboseLog)
		sentAny = sentAny || sent
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if sentAny {
		metricSentDiscoPeerToken.Add(1)
		return nil
	}
	if firstErr != nil {
		return firstErr
	}
	return errors.New("no path to peer")
}

// selfPeerToken is this node's own peer token, as given by control in the
// self node's CapMap under [nodecap.PeerToken].
type selfPeerToken struct {
	token []byte // compact serialized JWT; non-empty
}

// peerTokenCapValue is the JSON form of a [nodecap.PeerToken] value.
type peerTokenCapValue struct {
	Token string `json:"token"`
}

// peerTokenFromSelf returns the self node's own peer token, from the first
// [nodecap.PeerToken] value in its CapMap with a usable token, or nil if
// there's none.
func peerTokenFromSelf(self tailcfg.NodeView) ([]byte, error) {
	if !self.Valid() {
		return nil, nil
	}
	vals, err := tailcfg.UnmarshalNodeCapViewJSON[peerTokenCapValue](self.CapMap(), nodecap.PeerToken)
	for _, v := range vals {
		if n := len(v.Token); n > 0 && n <= disco.MaxPeerTokenLen {
			return []byte(v.Token), nil
		}
	}
	if err == nil && len(vals) > 0 {
		err = errors.New("no value has a token of valid length")
	}
	return nil, err
}

// updateSelfPeerTokenLocked updates c.selfPeerToken from self, the new self
// node. It stores a new pointer only if the token changed. c.mu must be held.
func (c *Conn) updateSelfPeerTokenLocked(self tailcfg.NodeView) {
	token, err := peerTokenFromSelf(self)
	if err != nil {
		c.logf("magicsock: invalid %s capability: %v", nodecap.PeerToken, err)
	}
	old := c.selfPeerToken.Load()
	switch {
	case token == nil:
		if old != nil {
			c.selfPeerToken.Store(nil)
		}
	case old == nil || !bytes.Equal(old.token, token):
		c.selfPeerToken.Store(&selfPeerToken{token: token})
	}
}

// peerTokenResendInterval is how long we go without hearing from a peer
// before presenting it our (unchanged) peer token again on the next contact
// attempt. The peer may have restarted and forgotten us, or the earlier
// message may have been lost or rate limited. It must exceed the granularity
// with which [endpoint.lastRecvWG] is updated (10s), so that a peer that's
// actively sending to us doesn't look idle.
const peerTokenResendInterval = 15 * time.Second

// maybeSendPeerTokenLocked presents our own peer token, if we have one, to
// the peer de, whose disco info is epDisco, unless we've already sent it the
// current token and either did so recently or have heard from the peer
// recently. The message is sent asynchronously.
//
// The peer may well already know us from control, in which case it ignores
// the token. We can't tell, so we send it to every peer we contact.
//
// de.mu must be held.
func (de *endpoint) maybeSendPeerTokenLocked(now mono.Time, epDisco *endpointDisco) {
	t := de.c.selfPeerToken.Load()
	if t == nil || epDisco == nil {
		return
	}
	if de.peerTokenSent == t {
		if now.Sub(de.peerTokenSentAt) < peerTokenResendInterval {
			return
		}
		lastRecv := max(de.lastRecvWG.LoadAtomic(), de.lastRecvUDPAny.LoadAtomic())
		if now.Sub(lastRecv) < peerTokenResendInterval {
			return
		}
	}
	de.peerTokenSent = t
	de.peerTokenSentAt = now
	dst, dstDisco, derpAddr, best := de.publicKey, epDisco.key(), de.derpAddr, de.bestAddr.epAddr
	go func() {
		if err := de.c.sendPeerToken(dst, dstDisco, t.token, derpAddr, best); err != nil {
			de.c.dlogf("[v1] magicsock: disco: sending peer token to %v: %v", dst.ShortString(), err)
		}
	}()
}
