// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tstime"
	"tailscale.com/tstime/rate"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/wgengine"
)

// This file implements finding peers that aren't in the netmap from control,
// by asking control with its peer lookup RPC (see [tailcfg.PeerLookupRequest]),
// which control offers (with [nodecap.PeerLookup]) when it relies on peer
// tokens rather than sending peers.
//
// A peer is looked up when this node wants to contact it, but doesn't have
// it:
//
//   - when wireguard-go has an outbound packet for a Tailscale IP with no
//     peer. That lookup is asynchronous, as it's on the packet path: the
//     packet is dropped, and retransmissions reach the peer once it's found.
//   - when the MagicDNS resolver is asked for a name in the tailnet's domain
//     that no peer has. That lookup is synchronous (with a short timeout), so
//     that the answer can include the peer.
//   - when "tailscale ping" is asked to ping a Tailscale IP with no peer.
//
// The peer found is injected as a [localPeer], like peers that present peer
// tokens (see peertoken.go), and is merged with any token it presents. Its
// lookup result expires after the TTL control gives, as its endpoints and
// home DERP region, which control doesn't send us updates of, may have
// changed. If we've sent the peer traffic recently, we look it up again then;
// otherwise we forget it (and remove it, if it hasn't also presented a token).
//
// Lookups are disabled while tailnet lock is enabled, as their results carry
// no node key signatures.

const (
	// peerLookupTimeout bounds each lookup RPC.
	peerLookupTimeout = 10 * time.Second

	// peerLookupDNSTimeout is how long a MagicDNS query waits for a lookup.
	peerLookupDNSTimeout = 3 * time.Second

	// peerLookupFailureTTL is how long after a failed lookup (because control
	// has no such peer, or because of an error) we don't look up the same
	// thing again.
	peerLookupFailureTTL = 10 * time.Second

	// minPeerLookupTTL and maxPeerLookupTTL bound how long we use a lookup
	// result, whatever TTL control gives.
	minPeerLookupTTL = 10 * time.Second
	maxPeerLookupTTL = time.Hour

	// peerLookupRetryInterval is how long we keep using a peer's expired
	// lookup result after failing to refresh it because of an error (as
	// opposed to control having no such peer), before trying again.
	peerLookupRetryInterval = 15 * time.Second

	// peerLookupRate and peerLookupBurst limit how often a node looks up
	// peers it doesn't have (but not how often it refreshes ones it has), so
	// that, say, a scan of the Tailscale IP range doesn't flood control.
	peerLookupRate  = 10 // per second
	peerLookupBurst = 20

	// maxPeerLookupFailures is how many failed lookups we remember before
	// pruning those that have expired.
	maxPeerLookupFailures = 256
)

var (
	metricPeerLookupFound    = clientmetric.NewCounter("localbackend_peer_lookup_found")
	metricPeerLookupNotFound = clientmetric.NewCounter("localbackend_peer_lookup_not_found")
	metricPeerLookupError    = clientmetric.NewCounter("localbackend_peer_lookup_error")
	metricPeerLookupExpired  = clientmetric.NewCounter("localbackend_peer_lookup_expired")

	metricPeerLookupRateLimited = clientmetric.NewCounter("localbackend_peer_lookup_rate_limited")
)

// errPeerLookupNotFound is returned by lookups for which control has no peer.
var errPeerLookupNotFound = errors.New("peer not found")

// errPeerLookupUnavailable is returned by lookups when this node can't look
// up peers: control doesn't offer it, or tailnet lock is enabled.
var errPeerLookupUnavailable = errors.New("peer lookup unavailable")

// errPeerLookupRateLimited is returned by lookups when this node has looked
// up too many peers recently.
var errPeerLookupRateLimited = errors.New("peer lookup rate limited")

// peerLookupQuery is what to look up a peer by: exactly one of ip and name.
type peerLookupQuery struct {
	ip   netip.Addr
	name string // a MagicDNS FQDN, lowercase without a trailing dot
}

func (q peerLookupQuery) String() string {
	if q.ip.IsValid() {
		return q.ip.String()
	}
	return q.name
}

// peerLookupResult is the result of a lookup RPC.
type peerLookupResult struct {
	node tailcfg.NodeView
	ttl  time.Duration
}

// doPeerLookup sends a lookup RPC to control. It returns
// errPeerLookupNotFound if control has no such peer.
func (b *LocalBackend) doPeerLookup(ctx context.Context, req *tailcfg.PeerLookupRequest) (*tailcfg.PeerLookupResponse, error) {
	if f := b.peerLookupFuncForTest; f != nil {
		return f(ctx, req)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, "POST", "https://unused/machine/peer-lookup", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	res, err := b.DoNoiseRequest(hreq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errPeerLookupNotFound
	default:
		return nil, fmt.Errorf("peer lookup: HTTP %d: %s", res.StatusCode, bytes.TrimSpace(resBody))
	}
	resp := new(tailcfg.PeerLookupResponse)
	if err := json.Unmarshal(resBody, resp); err != nil {
		return nil, fmt.Errorf("peer lookup: decoding response: %w", err)
	}
	return resp, nil
}

// canLookupPeersLocked reports whether control offers peer lookups to nb's
// self node. nb.mu must be held.
func (nb *nodeBackend) canLookupPeersLocked() bool {
	return nb.netMap != nil && nb.netMap.SelfNode.Valid() && nb.netMap.SelfNode.CapMap().Contains(nodecap.PeerLookup)
}

// peerLookupFailedRecentlyLocked reports whether a lookup of q failed within
// the last peerLookupFailureTTL as of now. nb.mu must be held.
func (nb *nodeBackend) peerLookupFailedRecentlyLocked(q peerLookupQuery, now time.Time) bool {
	t, ok := nb.peerLookupFailures[q]
	if !ok {
		return false
	}
	if now.Sub(t) < peerLookupFailureTTL {
		return true
	}
	delete(nb.peerLookupFailures, q)
	return false
}

// maybeLookupPeerByIPAsync starts looking up the peer with the Tailscale IP
// ip in the background, if control offers lookups and the IP isn't one we
// failed to look up recently. It's called on the packet path when there's no
// peer for ip, so it must be cheap.
func (b *LocalBackend) maybeLookupPeerByIPAsync(nb *nodeBackend, ip netip.Addr) {
	if !tsaddr.IsTailscaleIP(ip) || ip == tsaddr.TailscaleServiceIP() || ip == tsaddr.TailscaleServiceIPv6() {
		return
	}
	q := peerLookupQuery{ip: ip}
	if !nb.shouldStartPeerLookup(q, b.clock.Now()) {
		return
	}
	nb.peerLookups.DoChan(q, func() (tailcfg.NodeView, error) {
		return b.lookupPeer(nb, q)
	})
}

// shouldStartPeerLookup reports whether there's any point in looking up q
// as of now: control offers lookups, and we didn't recently fail to look up
// q.
func (nb *nodeBackend) shouldStartPeerLookup(q peerLookupQuery, now time.Time) bool {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.canLookupPeersLocked() && !nb.peerLookupFailedRecentlyLocked(q, now)
}

// lookupPeerWait looks up the peer for q, waiting for up to the context's
// deadline, and returns it. Concurrent lookups of the same q share one RPC.
func (b *LocalBackend) lookupPeerWait(ctx context.Context, nb *nodeBackend, q peerLookupQuery) (tailcfg.NodeView, error) {
	if !nb.shouldStartPeerLookup(q, b.clock.Now()) {
		return tailcfg.NodeView{}, errPeerLookupUnavailable
	}
	select {
	case res := <-nb.peerLookups.DoChan(q, func() (tailcfg.NodeView, error) {
		return b.lookupPeer(nb, q)
	}):
		return res.Val, res.Err
	case <-ctx.Done():
		return tailcfg.NodeView{}, ctx.Err()
	}
}

// lookupPeer looks up the peer for q with control, and injects it into nb
// as a local peer. It returns the peer's node as injected. Failures are
// recorded, so that the same q isn't looked up again for a while.
func (b *LocalBackend) lookupPeer(nb *nodeBackend, q peerLookupQuery) (tailcfg.NodeView, error) {
	if !nb.allowPeerLookup() {
		metricPeerLookupRateLimited.Add(1)
		return tailcfg.NodeView{}, errPeerLookupRateLimited
	}
	res, err := b.lookupPeerRPC(nb, q)
	switch {
	case errors.Is(err, errPeerLookupNotFound):
		metricPeerLookupNotFound.Add(1)
	case err != nil:
		metricPeerLookupError.Add(1)
		b.logf("peerlookup: looking up %v: %v", q, err)
	}
	var n tailcfg.NodeView
	if err == nil {
		n, err = b.addLookedUpPeer(nb, res)
		if err != nil {
			b.logf("peerlookup: adding peer for %v: %v", q, err)
		}
	}
	if err != nil {
		nb.notePeerLookupFailure(q, b.clock.Now())
		return tailcfg.NodeView{}, err
	}
	return n, nil
}

// allowPeerLookup reports whether nb may look up a peer now, under
// peerLookupRate.
func (nb *nodeBackend) allowPeerLookup() bool {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.peerLookupLimiter == nil {
		nb.peerLookupLimiter = rate.NewLimiter(peerLookupRate, peerLookupBurst)
	}
	return nb.peerLookupLimiter.Allow()
}

// notePeerLookupFailure records that a lookup of q failed at now, pruning
// expired failures if there are too many.
func (nb *nodeBackend) notePeerLookupFailure(q peerLookupQuery, now time.Time) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if len(nb.peerLookupFailures) >= maxPeerLookupFailures {
		for q, t := range nb.peerLookupFailures {
			if now.Sub(t) >= peerLookupFailureTTL {
				delete(nb.peerLookupFailures, q)
			}
		}
	}
	mak.Set(&nb.peerLookupFailures, q, now)
}

// lookupPeerRPC sends the lookup RPC for q on behalf of nb's self node, and
// checks the result.
func (b *LocalBackend) lookupPeerRPC(nb *nodeBackend, q peerLookupQuery) (*peerLookupResult, error) {
	b.mu.Lock()
	tka := b.tka
	b.mu.Unlock()
	if tka != nil {
		return nil, errPeerLookupUnavailable
	}
	nm := nb.NetMap()
	if nm == nil || nm.NodeKey.IsZero() {
		return nil, errPeerLookupUnavailable
	}

	ctx, cancel := context.WithTimeout(nb.ctx, peerLookupTimeout)
	defer cancel()
	resp, err := b.doPeerLookup(ctx, &tailcfg.PeerLookupRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nm.NodeKey,
		IP:      q.ip,
		Name:    q.name,
	})
	if err != nil {
		return nil, err
	}
	if resp.Node == nil {
		return nil, errors.New("peer lookup: no node in response")
	}
	n, err := checkLookedUpPeer(resp.Node, q)
	if err != nil {
		return nil, err
	}
	ttl := min(max(time.Duration(resp.TTLSeconds)*time.Second, minPeerLookupTTL), maxPeerLookupTTL)
	return &peerLookupResult{node: n, ttl: ttl}, nil
}

// checkLookedUpPeer checks that n, returned by control for a lookup of q, is
// usable as a peer and is what was asked for, and returns it ready to
// inject.
func checkLookedUpPeer(n *tailcfg.Node, q peerLookupQuery) (tailcfg.NodeView, error) {
	switch {
	case n.ID == 0:
		return tailcfg.NodeView{}, errors.New("peer lookup: node has no ID")
	case n.Key.IsZero():
		return tailcfg.NodeView{}, errors.New("peer lookup: node has no node key")
	case n.DiscoKey.IsZero():
		return tailcfg.NodeView{}, errors.New("peer lookup: node has no disco key")
	case len(n.Addresses) == 0:
		return tailcfg.NodeView{}, errors.New("peer lookup: node has no addresses")
	}
	for _, p := range n.Addresses {
		if !p.IsSingleIP() || !tsaddr.IsTailscaleIP(p.Addr()) {
			return tailcfg.NodeView{}, fmt.Errorf("peer lookup: node has invalid address %v", p)
		}
	}
	if q.ip.IsValid() && !tsaddr.PrefixesContainsIP(n.Addresses, q.ip) {
		return tailcfg.NodeView{}, fmt.Errorf("peer lookup: node for %v has addresses %v", q.ip, n.Addresses)
	}
	if q.name != "" && !strings.EqualFold(strings.TrimSuffix(n.Name, "."), q.name) {
		return tailcfg.NodeView{}, fmt.Errorf("peer lookup: node for %q is named %q", q.name, n.Name)
	}
	n = n.Clone()
	if len(n.AllowedIPs) == 0 {
		n.AllowedIPs = n.Addresses
	}
	if !n.Hostinfo.Valid() {
		n.Hostinfo = (&tailcfg.Hostinfo{}).View()
	}
	return n.View(), nil
}

// addLookedUpPeer injects the peer in res into nb, if nb is still current,
// and returns its node as injected.
func (b *LocalBackend) addLookedUpPeer(nb *nodeBackend, res *peerLookupResult) (tailcfg.NodeView, error) {
	var notify *ipn.Notify
	defer func() {
		if notify != nil {
			b.send(*notify)
		}
	}()

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.shutdownCalled || b.currentNode() != nb {
		return tailcfg.NodeView{}, errors.New("node changed")
	}
	if b.tka != nil {
		return tailcfg.NodeView{}, errPeerLookupUnavailable
	}
	now := b.clock.Now()
	id, expiry := res.node.ID(), now.Add(res.ttl)
	mut, n, err := nb.recordLookedUpPeer(res.node, expiry, func() tstime.TimerController {
		return b.clock.AfterFunc(res.ttl, func() { b.expireLookedUpPeer(nb, id, expiry) })
	})
	if err != nil {
		return tailcfg.NodeView{}, err
	}
	metricPeerLookupFound.Add(1)
	if mut != nil {
		b.logf("peerlookup: added peer %v (node %d, %q, %v) until %v",
			n.Key().ShortString(), id, n.Name(), n.Addresses().AsSlice(), expiry.UTC().Format(time.RFC3339))
		notify = b.applyNetmapDeltaLocked([]netmap.NodeMutation{mut}, false)
	}
	return n, nil
}

// recordLookedUpPeer records n, returned by a peer lookup and usable until
// expiry, as a local peer, after checking that it doesn't conflict with any
// other node in nb. newTimer is called to start the timer for expiry.
//
// It returns the mutation (if any) to apply to nb as a result, and the node
// now in nb for n's node ID. If control has already told us about the node,
// that's control's node, and nothing is recorded.
func (nb *nodeBackend) recordLookedUpPeer(n tailcfg.NodeView, expiry time.Time, newTimer func() tstime.TimerController) (netmap.NodeMutation, tailcfg.NodeView, error) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.netMap == nil {
		return nil, tailcfg.NodeView{}, errors.New("no netmap")
	}
	id := n.ID()
	lp := nb.localPeers[id]
	p, present := nb.peers[id]
	if present && lp == nil {
		// The node ID is that of a peer from control.
		if p.Key() == n.Key() {
			return nil, p, nil
		}
		return nil, tailcfg.NodeView{}, fmt.Errorf("node ID %d belongs to a different node in the netmap", id)
	}
	if err := checkLocalPeerConflicts(id, n.Key(), n.Addresses().AsSlice(), nb.netMap.SelfNode, nb.nodeByKey, nb.nodeByAddr); err != nil {
		return nil, tailcfg.NodeView{}, err
	}

	if lp == nil {
		lp = new(localPeer)
		mak.Set(&nb.localPeers, id, lp)
	}
	lp.clearLookup()
	lp.lookupNode, lp.lookupExpiry, lp.lookupTimer = n, expiry, newTimer()
	if lp.claims != nil && !sameKeys(lp.tokenNode, n) {
		// The peer's keys changed since it presented its token.
		lp.clearToken()
	}
	old := lp.node
	lp.node = localPeerNode(lp.tokenNode, lp.lookupNode)
	if present && old.Equal(lp.node) {
		return nil, lp.node, nil
	}
	return netmap.NodeMutationUpsert{Node: lp.node}, lp.node, nil
}

// expireLookedUpPeer handles the expiry of the lookup result, expiring at
// expiry, of the local peer with node ID id in nb. If we've sent the peer
// traffic recently, it looks the peer up again, keeping the old result
// until then; otherwise it forgets the result.
func (b *LocalBackend) expireLookedUpPeer(nb *nodeBackend, id tailcfg.NodeID, expiry time.Time) {
	nk, q, ok := nb.expiringLookedUpPeer(id, expiry)
	if !ok {
		return
	}
	if b.sentToPeerRecently(nk) {
		go b.refreshLookedUpPeer(nb, id, expiry, q)
		return
	}
	b.forgetLookedUpPeer(nb, id, expiry, "expired")
}

// expiringLookedUpPeer returns the node key of the local peer with node ID
// id, and a query to look it up again with, if its lookup result expires at
// expiry. Otherwise (if the result has since been replaced or forgotten), it
// reports false.
func (nb *nodeBackend) expiringLookedUpPeer(id tailcfg.NodeID, expiry time.Time) (_ key.NodePublic, _ peerLookupQuery, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	lp := nb.localPeers[id]
	if lp == nil || !lp.lookupNode.Valid() || !lp.lookupExpiry.Equal(expiry) {
		return key.NodePublic{}, peerLookupQuery{}, false
	}
	lp.lookupTimer = nil // it fired; stopping it from its own func can deadlock
	return lp.lookupNode.Key(), peerLookupQuery{ip: lp.lookupNode.Addresses().At(0).Addr()}, true
}

// sentToPeerRecently reports whether we sent traffic to the peer with node
// key nk within the last maxPeerLookupIdle.
func (b *LocalBackend) sentToPeerRecently(nk key.NodePublic) bool {
	f := b.sinceLastSendForTest
	if f == nil {
		ms := b.MagicConn()
		if ms == nil {
			return false
		}
		f = ms.SinceLastSendToNodeKey
	}
	d, ok := f(nk)
	return ok && d < maxPeerLookupIdle
}

// maxPeerLookupIdle is how long since we last sent a looked-up peer traffic
// that we stop looking it up again when its lookup result expires.
const maxPeerLookupIdle = 2 * time.Minute

// refreshLookedUpPeer looks up the local peer with node ID id again, with q,
// as its lookup result, expiring at expiry, expired while it was in use.
// If control no longer has the peer, it's forgotten. If the lookup fails for
// another reason, we keep using the old result for a while, and try again.
func (b *LocalBackend) refreshLookedUpPeer(nb *nodeBackend, id tailcfg.NodeID, expiry time.Time, q peerLookupQuery) {
	res, err := b.lookupPeerRPC(nb, q)
	if err == nil && res.node.ID() != id {
		err = errPeerLookupNotFound // the IP belongs to another node now
	}
	switch {
	case err == nil:
		if _, err := b.addLookedUpPeer(nb, res); err != nil {
			b.logf("peerlookup: refreshing node %d: %v", id, err)
			b.forgetLookedUpPeer(nb, id, expiry, "not refreshed")
		}
	case errors.Is(err, errPeerLookupNotFound), errors.Is(err, errPeerLookupUnavailable):
		metricPeerLookupNotFound.Add(1)
		b.forgetLookedUpPeer(nb, id, expiry, "gone")
	default:
		metricPeerLookupError.Add(1)
		b.logf("peerlookup: refreshing node %d: %v; retrying in %v", id, err, peerLookupRetryInterval)
		b.retryLookedUpPeerRefresh(nb, id, expiry)
	}
}

// retryLookedUpPeerRefresh extends the lookup result, expiring at expiry, of
// the local peer with node ID id in nb by peerLookupRetryInterval, after
// which it's handled as having expired again.
func (b *LocalBackend) retryLookedUpPeerRefresh(nb *nodeBackend, id tailcfg.NodeID, expiry time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.currentNode() != nb {
		return
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	lp := nb.localPeers[id]
	if lp == nil || !lp.lookupNode.Valid() || !lp.lookupExpiry.Equal(expiry) {
		return
	}
	newExpiry := b.clock.Now().Add(peerLookupRetryInterval)
	lp.lookupExpiry = newExpiry
	lp.lookupTimer = b.clock.AfterFunc(peerLookupRetryInterval, func() { b.expireLookedUpPeer(nb, id, newExpiry) })
}

// forgetLookedUpPeer forgets the lookup result, expiring at expiry, of the
// local peer with node ID id in nb, removing the peer unless it also has a
// token.
func (b *LocalBackend) forgetLookedUpPeer(nb *nodeBackend, id tailcfg.NodeID, expiry time.Time, why string) {
	var notify *ipn.Notify
	defer func() {
		if notify != nil {
			b.send(*notify)
		}
	}()

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.currentNode() != nb {
		return
	}
	mut, ok := nb.forgetLookupResult(id, expiry)
	if !ok {
		return
	}
	metricPeerLookupExpired.Add(1)
	b.logf("peerlookup: lookup of node %d %s", id, why)
	if mut != nil {
		notify = b.applyNetmapDeltaLocked([]netmap.NodeMutation{mut}, false)
	}
}

// forgetLookupResult forgets the lookup result of the local peer with node
// ID id if it expires at expiry. It reports whether it did (ok), and if so,
// the mutation (if any) for the caller to apply as a result.
func (nb *nodeBackend) forgetLookupResult(id tailcfg.NodeID, expiry time.Time) (_ netmap.NodeMutation, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	lp := nb.localPeers[id]
	if lp == nil || !lp.lookupNode.Valid() || !lp.lookupExpiry.Equal(expiry) {
		return nil, false
	}
	lp.clearLookup()
	return nb.localPeerChangedLocked(id, lp), true
}

// lookupPeerForDNS looks up the peer with the MagicDNS name fqdn, if it's a
// single label in the self node's MagicDNS domain, and returns the addresses
// to answer with, as [nodeBackend.magicDNSHostAddrs] does. It's called by the
// MagicDNS resolver for names that no peer has.
func (b *LocalBackend) lookupPeerForDNS(fqdn dnsname.FQDN) (ips []netip.Addr, ok bool) {
	nb := b.currentNode()
	if !b.lookupPeerByName(nb, string(fqdn), false) {
		return nil, false
	}
	return nb.magicDNSHostAddrs(fqdn)
}

// lookupPeerByName looks up the peer with the MagicDNS name name, if it's a
// single label in the self node's MagicDNS domain ("pi.foo.ts.net", with or
// without a trailing dot) or, if allowBare, a bare name ("pi"), which is
// taken to be in that domain. It waits up to peerLookupDNSTimeout, and
// reports whether it found the peer.
func (b *LocalBackend) lookupPeerByName(nb *nodeBackend, name string, allowBare bool) bool {
	suffix := strings.ToLower(strings.TrimSuffix(nb.NetMap().MagicDNSSuffix(), "."))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if suffix == "" || name == "" {
		return false
	}
	if allowBare && !strings.Contains(name, ".") {
		name += "." + suffix
	}
	base, ok := strings.CutSuffix(name, "."+suffix)
	if !ok || base == "" || strings.Contains(base, ".") {
		return false
	}
	ctx, cancel := context.WithTimeout(nb.ctx, peerLookupDNSTimeout)
	defer cancel()
	_, err := b.lookupPeerWait(ctx, nb, peerLookupQuery{name: name})
	return err == nil
}

// HasNodeAddr reports whether a node (self or peer) in nb has the Tailscale
// IP ip.
func (nb *nodeBackend) HasNodeAddr(ip netip.Addr) bool {
	_, ok := nb.NodeByAddr(ip)
	return ok
}

// PeerForIPWithLookup is like [LocalBackend.PeerForIP], but if no node has
// the Tailscale IP ip, it first waits briefly to look up the peer with
// control, if we may (see peerlookup.go).
//
// It's for dialers that only dial Tailscale IPs of known peers via
// netstack, as tailscaled does in userspace-networking mode, and tsnet
// does. Without it, they'd dial the IP of a peer we haven't found yet on
// the host's network instead, and so never find the peer.
func (b *LocalBackend) PeerForIPWithLookup(ip netip.Addr) (_ wgengine.PeerForIP, ok bool) {
	if p, ok := b.PeerForIP(ip); ok {
		return p, true
	}
	if !tsaddr.IsTailscaleIP(ip) || ip == tsaddr.TailscaleServiceIP() || ip == tsaddr.TailscaleServiceIPv6() {
		return wgengine.PeerForIP{}, false
	}
	nb := b.currentNode()
	ctx, cancel := context.WithTimeout(nb.ctx, peerLookupDNSTimeout)
	defer cancel()
	if _, err := b.lookupPeerWait(ctx, nb, peerLookupQuery{ip: ip}); err != nil {
		return wgengine.PeerForIP{}, false
	}
	return b.PeerForIP(ip)
}
