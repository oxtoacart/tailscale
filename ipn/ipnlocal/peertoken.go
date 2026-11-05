// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/peertoken"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
)

// This file implements accepting connections from peers that aren't in the
// netmap from control, but which present a control-signed peer token (see
// package peertoken) in a disco message.
//
// A verified token yields a synthesized [tailcfg.Node] that is injected into
// the current [nodeBackend] via the same delta path as control's incremental
// netmap updates, so magicsock, the WireGuard device, the route manager and
// the packet filter all treat it like any other peer. The node carries the
// peer capability named by the token, which "cap:..." packet filter rules
// (from the self node's CapMap) match on. The node is removed when its token
// expires, unless the peer has sent a newer token by then.

var (
	metricPeerTokenAccepted = clientmetric.NewCounter("localbackend_peer_token_accepted")
	metricPeerTokenRenewed  = clientmetric.NewCounter("localbackend_peer_token_renewed")
	metricPeerTokenRejected = clientmetric.NewCounter("localbackend_peer_token_rejected")
	metricPeerTokenExpired  = clientmetric.NewCounter("localbackend_peer_token_expired")
)

var errPeerTokenTailnetLock = errors.New("tailnet lock is enabled; peer tokens signed by control are not trusted")

// tokenPeer is a peer authorized by a peer token.
type tokenPeer struct {
	claims *peertoken.Claims
	token  string
	node   tailcfg.NodeView // as injected into nodeBackend.peers
	timer  tstime.TimerController
}

// handlePeerToken is the [magicsock.Conn] peer token handler. It verifies the
// token in m and, if valid, adds (or refreshes) the peer it describes.
func (b *LocalBackend) handlePeerToken(m magicsock.PeerTokenMessage) {
	var notify *ipn.Notify
	defer func() {
		if notify != nil {
			b.send(*notify)
		}
	}()

	b.mu.Lock()
	defer b.mu.Unlock()

	var err error
	notify, err = b.acceptPeerTokenLocked(m)
	if err != nil {
		metricPeerTokenRejected.Add(1)
		b.logf("peertoken: rejected token from disco %v: %v", m.DiscoKey.ShortString(), err)
	}
}

// verifyPeerToken verifies token against the signing keys in the self node's
// CapMap, and checks that self has the "cap:..." CapMap entry named by the
// token.
func verifyPeerToken(self tailcfg.NodeView, token string, now time.Time) (*peertoken.Claims, error) {
	ks, _ := peertoken.KeySetFromSelfCapMap(self.CapMap())
	c, err := peertoken.Verify(token, ks, now)
	if err != nil {
		return nil, err
	}
	if !self.CapMap().Contains(c.SelfCapMapKey()) {
		return nil, fmt.Errorf("control did not grant this node %q", c.SelfCapMapKey())
	}
	return c, nil
}

// acceptPeerTokenLocked implements [LocalBackend.handlePeerToken]. It
// returns a Notify for the caller to send after releasing b.mu, if any.
//
// b.mu must be held.
func (b *LocalBackend) acceptPeerTokenLocked(m magicsock.PeerTokenMessage) (*ipn.Notify, error) {
	if b.shutdownCalled {
		return nil, nil
	}
	if b.tka != nil {
		return nil, errPeerTokenTailnetLock
	}
	cn := b.currentNode()
	nm := cn.NetMap()
	if nm == nil || !nm.SelfNode.Valid() {
		return nil, errors.New("no netmap")
	}
	now := b.clock.Now()
	c, err := verifyPeerToken(nm.SelfNode, m.Token, now)
	if err != nil {
		return nil, err
	}
	// Bind the token to the transport: the disco message must have been
	// sealed by the token's disco key, and if it came via DERP (which
	// authenticates the sending node key), from the token's node key.
	if c.DiscoKey != m.DiscoKey {
		return nil, fmt.Errorf("token is for disco key %v, but message was sealed by %v", c.DiscoKey.ShortString(), m.DiscoKey.ShortString())
	}
	if !m.DERPNodeKey.IsZero() && m.DERPNodeKey != c.NodeKey {
		return nil, fmt.Errorf("token is for node key %v, but message came via DERP from %v", c.NodeKey.ShortString(), m.DERPNodeKey.ShortString())
	}

	nodeID, expiry := c.NodeID, c.Expiry
	n, renewed, err := cn.recordTokenPeer(c, m, func() tstime.TimerController {
		return b.clock.AfterFunc(expiry.Sub(now), func() { b.expireTokenPeer(cn, nodeID, expiry) })
	})
	if err != nil {
		return nil, err
	}
	if renewed {
		metricPeerTokenRenewed.Add(1)
	}
	if !n.Valid() {
		return nil, nil
	}
	if !renewed {
		metricPeerTokenAccepted.Add(1)
		b.logf("peertoken: accepted peer %v (node %d, %v, cap %q) until %v",
			c.NodeKey.ShortString(), c.NodeID, c.Addresses, c.PeerCap(), c.Expiry.UTC().Format(time.RFC3339))
	}
	return b.applyNetmapDeltaLocked([]netmap.NodeMutation{netmap.NodeMutationUpsert{Node: n}}, false), nil
}

// expireTokenPeer removes the token peer with the given node ID from nb, if
// nb is still current and the peer's token still expires at expiry (that is,
// the peer has not since presented a newer token).
func (b *LocalBackend) expireTokenPeer(nb *nodeBackend, id tailcfg.NodeID, expiry time.Time) {
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
	stillPresent, ok := nb.forgetExpiredTokenPeer(id, expiry)
	if !ok {
		return
	}
	metricPeerTokenExpired.Add(1)
	b.logf("peertoken: token for node %d expired", id)
	if stillPresent {
		notify = b.applyNetmapDeltaLocked([]netmap.NodeMutation{netmap.MakeNodeMutationRemove(id)}, false)
	}
}

// forgetTokenPeersForControlMutsLocked drops any token peers whose node IDs
// control upserts or removes in muts. Control is authoritative for those
// nodes from now on, so the mutations are applied as-is; we merely stop
// managing (and expiring) them ourselves.
//
// b.mu must be held.
func (b *LocalBackend) forgetTokenPeersForControlMutsLocked(muts []netmap.NodeMutation) {
	cn := b.currentNode()
	cn.mu.Lock()
	defer cn.mu.Unlock()
	if len(cn.tokenPeers) == 0 {
		return
	}
	for _, m := range muts {
		switch m.(type) {
		case netmap.NodeMutationUpsert, netmap.NodeMutationRemove:
			cn.forgetTokenPeerLocked(m.NodeIDBeingMutated())
		}
	}
}

// mergeTokenPeersLocked returns nm with the current token peers that remain
// valid added to nm.Peers, for installing as the new full netmap. Token peers
// that are no longer valid under nm (expired, signing key or capability
// revoked, superseded or conflicting with a peer from control, or tailnet lock
// enabled) are forgotten. It returns nm unmodified if there's nothing to
// merge; otherwise a shallow copy.
//
// b.mu must be held.
func (b *LocalBackend) mergeTokenPeersLocked(nm *netmap.NetworkMap) *netmap.NetworkMap {
	var verify func(string) (*peertoken.Claims, error)
	if nm != nil && nm.SelfNode.Valid() && b.tka == nil {
		now := b.clock.Now()
		verify = func(token string) (*peertoken.Claims, error) {
			return verifyPeerToken(nm.SelfNode, token, now)
		}
	}
	return b.currentNode().mergeTokenPeers(nm, verify)
}

// recordTokenPeer records the peer described by the verified claims c,
// received in m, as a token peer, after checking that it doesn't conflict with
// any other node in nb.
//
// If a peer must be upserted into nb as a result, it returns its node (and
// otherwise the zero NodeView). It reports whether the claims renewed an
// existing token peer. newTimer is called to start the expiry timer for the
// newly recorded token.
func (nb *nodeBackend) recordTokenPeer(c *peertoken.Claims, m magicsock.PeerTokenMessage, newTimer func() tstime.TimerController) (_ tailcfg.NodeView, renewed bool, _ error) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.netMap == nil {
		return tailcfg.NodeView{}, false, errors.New("no netmap")
	}

	// A tokenPeers entry means we (not control) manage the node with that
	// ID: control upserts and removes clear the entry.
	prev := nb.tokenPeers[c.NodeID]
	if p, ok := nb.peers[c.NodeID]; ok && prev == nil {
		// The node ID is that of a peer from control.
		if p.Key() == c.NodeKey {
			// We already know this peer from control. Nothing to do.
			return tailcfg.NodeView{}, false, nil
		}
		return tailcfg.NodeView{}, false, fmt.Errorf("node ID %d belongs to a different node in the netmap", c.NodeID)
	}
	if err := checkTokenPeerConflicts(c, nb.netMap.SelfNode, nb.nodeByKey, nb.nodeByAddr); err != nil {
		return tailcfg.NodeView{}, false, err
	}

	if prev != nil && !c.Expiry.After(prev.claims.Expiry) {
		// Not newer than the token we have; perhaps a retransmission or
		// replay. Ignore it.
		return tailcfg.NodeView{}, false, nil
	}

	n := tokenPeerNode(c, m, prev)
	if prev != nil {
		prev.timer.Stop()
	}
	mak.Set(&nb.tokenPeers, c.NodeID, &tokenPeer{
		claims: c,
		token:  m.Token,
		node:   n,
		timer:  newTimer(),
	})
	return n, prev != nil, nil
}

// checkTokenPeerConflicts reports an error if the peer described by c
// would collide with self or with another node (by node key or address), as
// indexed by nodeByKey and nodeByAddr. Index entries for c.NodeID itself
// don't count as conflicts.
func checkTokenPeerConflicts(c *peertoken.Claims, self tailcfg.NodeView, nodeByKey map[key.NodePublic]tailcfg.NodeID, nodeByAddr map[netip.Addr]tailcfg.NodeID) error {
	if self.Valid() && (self.ID() == c.NodeID || self.Key() == c.NodeKey) {
		return errors.New("token describes this node")
	}
	if id, ok := nodeByKey[c.NodeKey]; ok && id != c.NodeID {
		return fmt.Errorf("node key %v belongs to node %d", c.NodeKey.ShortString(), id)
	}
	for _, p := range c.Addresses {
		if id, ok := nodeByAddr[p.Addr()]; ok && id != c.NodeID {
			return fmt.Errorf("address %v belongs to node %d", p.Addr(), id)
		}
	}
	return nil
}

// tokenPeerNode synthesizes the peer node for the verified claims c,
// received in m. If prev is non-nil, it's the token peer being renewed, whose
// learned endpoints are carried forward if m doesn't supply new ones.
func tokenPeerNode(c *peertoken.Claims, m magicsock.PeerTokenMessage, prev *tokenPeer) tailcfg.NodeView {
	n := &tailcfg.Node{
		ID:                c.NodeID,
		StableID:          tailcfg.StableNodeID(cmp.Or(c.Subject, fmt.Sprintf("peertoken-%d", c.NodeID))),
		Key:               c.NodeKey,
		KeyExpiry:         c.Expiry,
		DiscoKey:          c.DiscoKey,
		Addresses:         slices.Clone(c.Addresses),
		AllowedIPs:        slices.Clone(c.Addresses),
		Hostinfo:          (&tailcfg.Hostinfo{}).View(),
		MachineAuthorized: true,
		CapMap:            tailcfg.NodeCapMap{c.PeerCap(): nil},
		HomeDERP:          tailcfg.DERPRegionID(m.DERPRegion),
	}
	if m.UDPSrc.IsValid() {
		n.Endpoints = []netip.AddrPort{m.UDPSrc}
	}
	if prev != nil {
		if n.HomeDERP == 0 {
			n.HomeDERP = prev.node.HomeDERP()
		}
		if len(n.Endpoints) == 0 {
			n.Endpoints = prev.node.Endpoints().AsSlice()
		}
	}
	return n.View()
}

// forgetExpiredTokenPeer forgets the token peer with the given ID if its
// token expires at expiry. It reports whether it did (ok), and if so, whether
// the peer is still present in nb.peers (and so must be removed by the
// caller).
func (nb *nodeBackend) forgetExpiredTokenPeer(id tailcfg.NodeID, expiry time.Time) (stillPresent, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	tp := nb.tokenPeers[id]
	if tp == nil || !tp.claims.Expiry.Equal(expiry) {
		return false, false
	}
	delete(nb.tokenPeers, id)
	_, present := nb.peers[id]
	return present, true
}

// forgetTokenPeerLocked stops managing the token peer with the given ID, if
// any. It doesn't remove the peer from nb.peers. nb.mu must be held.
func (nb *nodeBackend) forgetTokenPeerLocked(id tailcfg.NodeID) {
	if tp, ok := nb.tokenPeers[id]; ok {
		tp.timer.Stop()
		delete(nb.tokenPeers, id)
	}
}

// mergeTokenPeers implements [LocalBackend.mergeTokenPeersLocked]. If verify
// is nil, all token peers are forgotten.
func (nb *nodeBackend) mergeTokenPeers(nm *netmap.NetworkMap, verify func(token string) (*peertoken.Claims, error)) *netmap.NetworkMap {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if len(nb.tokenPeers) == 0 {
		return nm
	}
	if nm == nil || verify == nil {
		for id := range nb.tokenPeers {
			nb.forgetTokenPeerLocked(id)
		}
		return nm
	}

	byID := make(map[tailcfg.NodeID]tailcfg.NodeView, len(nm.Peers))
	nodeByKey := make(map[key.NodePublic]tailcfg.NodeID, len(nm.Peers))
	nodeByAddr := make(map[netip.Addr]tailcfg.NodeID, len(nm.Peers))
	for _, p := range nm.Peers {
		byID[p.ID()] = p
		nodeByKey[p.Key()] = p.ID()
		for _, pfx := range p.Addresses().All() {
			if pfx.IsSingleIP() {
				nodeByAddr[pfx.Addr()] = p.ID()
			}
		}
	}

	var (
		add  []tailcfg.NodeView
		drop set.Set[tailcfg.NodeID] // our own copies already in nm.Peers
	)
	for id, tp := range nb.tokenPeers {
		if p, ok := byID[id]; ok {
			if !p.Equal(tp.node) {
				// Control now tells us about this node; it's authoritative.
				nb.forgetTokenPeerLocked(id)
				continue
			}
			// nm already contains our copy (for instance, when the current
			// netmap is reinstalled). Re-validate it like the others.
			drop.Make()
			drop.Add(id)
		}
		if _, err := verify(tp.token); err != nil {
			nb.logf("peertoken: dropping peer %d: %v", id, err)
			nb.forgetTokenPeerLocked(id)
			continue
		}
		if err := checkTokenPeerConflicts(tp.claims, nm.SelfNode, nodeByKey, nodeByAddr); err != nil {
			nb.logf("peertoken: dropping peer %d: %v", id, err)
			nb.forgetTokenPeerLocked(id)
			continue
		}
		add = append(add, tp.node)
	}
	if len(add) == 0 && len(drop) == 0 {
		return nm
	}

	merged := new(netmap.NetworkMap)
	*merged = *nm
	merged.Peers = make([]tailcfg.NodeView, 0, len(nm.Peers)+len(add))
	for _, p := range nm.Peers {
		if !drop.Contains(p.ID()) {
			merged.Peers = append(merged.Peers, p)
		}
	}
	merged.Peers = append(merged.Peers, add...)
	slices.SortFunc(merged.Peers, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
	return merged
}

// updateTokenPeerFilterLocked recomputes nb.tokenPeerFilter from the self
// node's CapMap. nb.mu must be held.
func (nb *nodeBackend) updateTokenPeerFilterLocked() {
	nb.tokenPeerFilter = nil
	nb.packetFilterWithTokenPeers = nil
	if nb.netMap == nil || !nb.netMap.SelfNode.Valid() {
		return
	}
	rules, err := peertoken.FilterRulesFromSelfCapMap(nb.netMap.SelfNode.CapMap())
	if err != nil {
		nb.logf("peertoken: %v", err)
	}
	if len(rules) == 0 {
		return
	}
	matches, err := filter.MatchesFromFilterRules(rules)
	if err != nil {
		nb.logf("peertoken: parsing filter rules: %v", err)
	}
	nb.tokenPeerFilter = matches
}

// packetFilterWithTokenPeerRules returns the live packet filter matches from
// control plus those for token peers from the self node's CapMap. It returns
// the same slice on successive calls until either changes.
func (nb *nodeBackend) packetFilterWithTokenPeerRules() []filter.Match {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if len(nb.tokenPeerFilter) == 0 {
		return nb.packetFilter
	}
	if nb.packetFilterWithTokenPeers == nil {
		nb.packetFilterWithTokenPeers = slices.Concat(nb.packetFilter, nb.tokenPeerFilter)
	}
	return nb.packetFilterWithTokenPeers
}
