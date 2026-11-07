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
	"tailscale.com/tailcfg/nodecap"
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
// the packet filter all treat it like any other peer. The node carries those
// of the token's capabilities that this node grants (see
// [peertoken.Claims.GrantedPeerCaps]), which "cap:..." packet filter rules
// (from the self node's CapMap) match on. The granted capabilities are
// recomputed with each full netmap. The node is removed when its token
// expires, unless the peer has sent a newer token by then.
//
// Peers that this node looks up with control's peer lookup RPC (see
// peerlookup.go) are injected the same way. Each such "local" peer (one we,
// rather than control, put in the netmap) is a [localPeer], from a token, a
// lookup or both, and stays until neither remains valid.

var (
	metricPeerTokenAccepted = clientmetric.NewCounter("localbackend_peer_token_accepted")
	metricPeerTokenRenewed  = clientmetric.NewCounter("localbackend_peer_token_renewed")
	metricPeerTokenRejected = clientmetric.NewCounter("localbackend_peer_token_rejected")
	metricPeerTokenExpired  = clientmetric.NewCounter("localbackend_peer_token_expired")
)

var errPeerTokenTailnetLock = errors.New("tailnet lock is enabled; peer tokens signed by control are not trusted")

// localPeer is a peer that this node, rather than control, put in its
// netmap: one that presented a valid peer token, one that this node looked up
// with control's peer lookup RPC, or both.
type localPeer struct {
	// claims, if non-nil, are those of the peer's current token, from which
	// tokenNode was synthesized. tokenTimer fires when the token expires.
	claims     *peertoken.Claims
	token      string
	tokenNode  tailcfg.NodeView
	tokenTimer tstime.TimerController

	// lookupNode, if valid, is the peer as returned by a peer lookup, which
	// may be used until lookupExpiry, when lookupTimer fires.
	lookupNode   tailcfg.NodeView
	lookupExpiry time.Time
	lookupTimer  tstime.TimerController

	node tailcfg.NodeView // as injected into nodeBackend.peers; see localPeerNode
}

// clearToken forgets lp's token, if any.
func (lp *localPeer) clearToken() {
	if lp.tokenTimer != nil {
		lp.tokenTimer.Stop()
	}
	lp.claims, lp.token, lp.tokenNode, lp.tokenTimer = nil, "", tailcfg.NodeView{}, nil
}

// clearLookup forgets lp's lookup result, if any.
func (lp *localPeer) clearLookup() {
	if lp.lookupTimer != nil {
		lp.lookupTimer.Stop()
	}
	lp.lookupNode, lp.lookupExpiry, lp.lookupTimer = tailcfg.NodeView{}, time.Time{}, nil
}

// empty reports whether lp has neither a token nor a lookup result, and so
// should be forgotten.
func (lp *localPeer) empty() bool {
	return lp.claims == nil && !lp.lookupNode.Valid()
}

// localPeerNode returns the node to inject for a local peer with the given
// token and lookup nodes, either of which may be invalid (but not both).
//
// With both, it's the looked-up node (which has the peer's name, real key
// expiry, home DERP region and endpoints, from control), with the token's
// granted capabilities (which the packet filter matches inbound traffic from
// the peer on), and any endpoint we learned from the token's disco message.
func localPeerNode(tokenNode, lookupNode tailcfg.NodeView) tailcfg.NodeView {
	switch {
	case !lookupNode.Valid():
		return tokenNode
	case !tokenNode.Valid():
		return lookupNode
	}
	n := lookupNode.AsStruct()
	n.CapMap = tokenNode.CapMap().AsMap()
	for _, ep := range tokenNode.Endpoints().All() {
		if !slices.Contains(n.Endpoints, ep) {
			n.Endpoints = append(n.Endpoints, ep)
		}
	}
	if n.HomeDERP == 0 {
		n.HomeDERP = tokenNode.HomeDERP()
	}
	return n.View()
}

// sameKeys reports whether a and b have the same node and disco keys. If a
// local peer's token and lookup result don't, the peer has changed keys
// since one of them, so the older one should be forgotten.
func sameKeys(a, b tailcfg.NodeView) bool {
	return a.Key() == b.Key() && a.DiscoKey() == b.DiscoKey()
}

// localPeerChangedLocked updates the local peer lp with node ID id, after a
// change to its token or lookup result, and returns the mutation (if any) to
// apply to nb's peers as a result. If lp is now empty, it's forgotten and the
// peer removed. nb.mu must be held.
func (nb *nodeBackend) localPeerChangedLocked(id tailcfg.NodeID, lp *localPeer) netmap.NodeMutation {
	_, present := nb.peers[id]
	if lp.empty() {
		delete(nb.localPeers, id)
		if !present {
			return nil
		}
		return netmap.MakeNodeMutationRemove(id)
	}
	old := lp.node
	lp.node = localPeerNode(lp.tokenNode, lp.lookupNode)
	if !present || old.Equal(lp.node) {
		return nil
	}
	return netmap.NodeMutationUpsert{Node: lp.node}
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
// CapMap, and returns its claims and the peer capabilities that self grants
// it: those of the token's caps that have a "cap:..." entry in self's CapMap.
// It reports an error if self grants none of them.
func verifyPeerToken(self tailcfg.NodeView, token string, now time.Time) (*peertoken.Claims, []nodecap.Cap, error) {
	ks, _ := peertoken.KeySetFromSelfCapMap(self.CapMap())
	c, err := peertoken.Verify(token, ks, now)
	if err != nil {
		return nil, nil, err
	}
	granted := c.GrantedPeerCaps(self.CapMap())
	if len(granted) == 0 {
		return nil, nil, fmt.Errorf("control granted this node none of the token's caps %q", c.Caps)
	}
	return c, granted, nil
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
	c, granted, err := verifyPeerToken(nm.SelfNode, m.Token, now)
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
	n, renewed, err := cn.recordTokenPeer(c, granted, m, func() tstime.TimerController {
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
		b.logf("peertoken: accepted peer %v (node %d, %v, caps %q) until %v",
			c.NodeKey.ShortString(), c.NodeID, c.Addresses, granted, c.Expiry.UTC().Format(time.RFC3339))
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
	mut, ok := nb.forgetExpiredTokenPeer(id, expiry)
	if !ok {
		return
	}
	metricPeerTokenExpired.Add(1)
	b.logf("peertoken: token for node %d expired", id)
	if mut != nil {
		notify = b.applyNetmapDeltaLocked([]netmap.NodeMutation{mut}, false)
	}
}

// forgetLocalPeersForControlMutsLocked drops any local peers whose node IDs
// control upserts or removes in muts. Control is authoritative for those
// nodes from now on, so the mutations are applied as-is; we merely stop
// managing (and expiring) them ourselves.
//
// b.mu must be held.
func (b *LocalBackend) forgetLocalPeersForControlMutsLocked(muts []netmap.NodeMutation) {
	cn := b.currentNode()
	cn.mu.Lock()
	defer cn.mu.Unlock()
	if len(cn.localPeers) == 0 {
		return
	}
	for _, m := range muts {
		switch m.(type) {
		case netmap.NodeMutationUpsert, netmap.NodeMutationRemove:
			cn.forgetLocalPeerLocked(m.NodeIDBeingMutated())
		}
	}
}

// mergeLocalPeersLocked returns nm with the current local peers that remain
// valid added to nm.Peers, for installing as the new full netmap. Tokens that
// are no longer valid under nm (expired, or signing key or capability
// revoked) are forgotten, as are local peers that are superseded by or
// conflict with a peer from control, and all local peers if tailnet lock is
// enabled. It returns nm unmodified if there's nothing to merge; otherwise a
// shallow copy.
//
// b.mu must be held.
func (b *LocalBackend) mergeLocalPeersLocked(nm *netmap.NetworkMap) *netmap.NetworkMap {
	var verify func(string) (*peertoken.Claims, []nodecap.Cap, error)
	if nm != nil && nm.SelfNode.Valid() && b.tka == nil {
		now := b.clock.Now()
		verify = func(token string) (*peertoken.Claims, []nodecap.Cap, error) {
			return verifyPeerToken(nm.SelfNode, token, now)
		}
	}
	return b.currentNode().mergeLocalPeers(nm, verify)
}

// recordTokenPeer records the peer described by the verified claims c,
// received in m, as a token peer with the peer capabilities granted, after
// checking that it doesn't conflict with any other node in nb.
//
// If a peer must be upserted into nb as a result, it returns its node (and
// otherwise the zero NodeView). It reports whether the claims renewed an
// existing token peer. newTimer is called to start the expiry timer for the
// newly recorded token.
func (nb *nodeBackend) recordTokenPeer(c *peertoken.Claims, granted []nodecap.Cap, m magicsock.PeerTokenMessage, newTimer func() tstime.TimerController) (_ tailcfg.NodeView, renewed bool, _ error) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.netMap == nil {
		return tailcfg.NodeView{}, false, errors.New("no netmap")
	}

	// A localPeers entry means we (not control) manage the node with that
	// ID: control upserts and removes clear the entry.
	lp := nb.localPeers[c.NodeID]
	if p, ok := nb.peers[c.NodeID]; ok && lp == nil {
		// The node ID is that of a peer from control.
		if p.Key() == c.NodeKey {
			// We already know this peer from control. Nothing to do.
			return tailcfg.NodeView{}, false, nil
		}
		return tailcfg.NodeView{}, false, fmt.Errorf("node ID %d belongs to a different node in the netmap", c.NodeID)
	}
	if err := checkLocalPeerConflicts(c.NodeID, c.NodeKey, c.Addresses, nb.netMap.SelfNode, nb.nodeByKey, nb.nodeByAddr); err != nil {
		return tailcfg.NodeView{}, false, err
	}

	if lp != nil && lp.claims != nil && !c.Expiry.After(lp.claims.Expiry) {
		// Not newer than the token we have; perhaps a retransmission or
		// replay. Ignore it.
		return tailcfg.NodeView{}, false, nil
	}

	if lp == nil {
		lp = new(localPeer)
		mak.Set(&nb.localPeers, c.NodeID, lp)
	}
	renewed = lp.claims != nil
	prevTokenNode := lp.tokenNode
	lp.clearToken()
	lp.claims, lp.token = c, m.Token
	lp.tokenNode = tokenPeerNode(c, granted, m, prevTokenNode)
	lp.tokenTimer = newTimer()
	if lp.lookupNode.Valid() && !sameKeys(lp.lookupNode, lp.tokenNode) {
		// The peer's keys changed since we looked it up.
		lp.clearLookup()
	}
	lp.node = localPeerNode(lp.tokenNode, lp.lookupNode)
	return lp.node, renewed, nil
}

// checkLocalPeerConflicts reports an error if the local peer with the given
// node ID, node key and addresses would collide with self or with another
// node (by node key or address), as indexed by nodeByKey and nodeByAddr.
// Index entries for nodeID itself don't count as conflicts.
func checkLocalPeerConflicts(nodeID tailcfg.NodeID, nodeKey key.NodePublic, addrs []netip.Prefix, self tailcfg.NodeView, nodeByKey map[key.NodePublic]tailcfg.NodeID, nodeByAddr map[netip.Addr]tailcfg.NodeID) error {
	if self.Valid() && (self.ID() == nodeID || self.Key() == nodeKey) {
		return errors.New("peer is this node")
	}
	if id, ok := nodeByKey[nodeKey]; ok && id != nodeID {
		return fmt.Errorf("node key %v belongs to node %d", nodeKey.ShortString(), id)
	}
	for _, p := range addrs {
		if id, ok := nodeByAddr[p.Addr()]; ok && id != nodeID {
			return fmt.Errorf("address %v belongs to node %d", p.Addr(), id)
		}
	}
	return nil
}

// tokenPeerNode synthesizes the peer node for the verified claims c,
// received in m, with the peer capabilities granted. If prev is valid, it's
// the node from the token being renewed, whose learned endpoints are carried
// forward if m doesn't supply new ones.
func tokenPeerNode(c *peertoken.Claims, granted []nodecap.Cap, m magicsock.PeerTokenMessage, prev tailcfg.NodeView) tailcfg.NodeView {
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
		CapMap:            tokenPeerCapMap(granted),
		HomeDERP:          tailcfg.DERPRegionID(m.DERPRegion),
	}
	if m.UDPSrc.IsValid() {
		n.Endpoints = []netip.AddrPort{m.UDPSrc}
	}
	if prev.Valid() {
		if n.HomeDERP == 0 {
			n.HomeDERP = prev.HomeDERP()
		}
		if len(n.Endpoints) == 0 {
			n.Endpoints = prev.Endpoints().AsSlice()
		}
	}
	return n.View()
}

// tokenPeerCapMap returns the CapMap for a token peer granted the given peer
// capabilities.
func tokenPeerCapMap(granted []nodecap.Cap) tailcfg.NodeCapMap {
	m := make(tailcfg.NodeCapMap, len(granted))
	for _, c := range granted {
		m[c] = nil
	}
	return m
}

// withGrantedCaps returns n with its CapMap replaced by the given granted
// peer capabilities, or n itself if it already has exactly those.
func withGrantedCaps(n tailcfg.NodeView, granted []nodecap.Cap) tailcfg.NodeView {
	if n.CapMap().Len() == len(granted) && !slices.ContainsFunc(granted, func(c nodecap.Cap) bool {
		return !n.CapMap().Contains(c)
	}) {
		return n
	}
	ns := n.AsStruct()
	ns.CapMap = tokenPeerCapMap(granted)
	return ns.View()
}

// forgetExpiredTokenPeer forgets the token of the local peer with the given
// ID if it expires at expiry. It reports whether it did (ok), and if so, the
// mutation (if any) for the caller to apply as a result: removing the peer,
// or, if it has a lookup result too, updating it to be just that.
func (nb *nodeBackend) forgetExpiredTokenPeer(id tailcfg.NodeID, expiry time.Time) (_ netmap.NodeMutation, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	lp := nb.localPeers[id]
	if lp == nil || lp.claims == nil || !lp.claims.Expiry.Equal(expiry) {
		return nil, false
	}
	lp.tokenTimer = nil // it fired; stopping it from its own func can deadlock
	lp.clearToken()
	return nb.localPeerChangedLocked(id, lp), true
}

// forgetLocalPeerLocked stops managing the local peer with the given ID, if
// any. It doesn't remove the peer from nb.peers. nb.mu must be held.
func (nb *nodeBackend) forgetLocalPeerLocked(id tailcfg.NodeID) {
	if lp, ok := nb.localPeers[id]; ok {
		lp.clearToken()
		lp.clearLookup()
		delete(nb.localPeers, id)
	}
}

// mergeLocalPeers implements [LocalBackend.mergeLocalPeersLocked]. If verify
// is nil, all local peers are forgotten. Otherwise verify reports the peer
// capabilities granted to each local peer's token under nm, and the peer's
// node is updated to carry exactly those.
func (nb *nodeBackend) mergeLocalPeers(nm *netmap.NetworkMap, verify func(token string) (*peertoken.Claims, []nodecap.Cap, error)) *netmap.NetworkMap {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if len(nb.localPeers) == 0 {
		return nm
	}
	if nm == nil || verify == nil {
		for id := range nb.localPeers {
			nb.forgetLocalPeerLocked(id)
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
	for id, lp := range nb.localPeers {
		if p, ok := byID[id]; ok {
			if !p.Equal(lp.node) {
				// Control now tells us about this node; it's authoritative.
				nb.forgetLocalPeerLocked(id)
				continue
			}
			// nm already contains our copy (for instance, when the current
			// netmap is reinstalled). Re-validate it like the others.
			drop.Make()
			drop.Add(id)
		}
		if lp.claims != nil {
			if _, granted, err := verify(lp.token); err != nil {
				nb.logf("peertoken: dropping token of peer %d: %v", id, err)
				lp.clearToken()
			} else {
				lp.tokenNode = withGrantedCaps(lp.tokenNode, granted)
			}
		}
		if lp.empty() {
			nb.forgetLocalPeerLocked(id)
			continue
		}
		lp.node = localPeerNode(lp.tokenNode, lp.lookupNode)
		if err := checkLocalPeerConflicts(id, lp.node.Key(), lp.node.Addresses().AsSlice(), nm.SelfNode, nodeByKey, nodeByAddr); err != nil {
			nb.logf("peertoken: dropping peer %d: %v", id, err)
			nb.forgetLocalPeerLocked(id)
			continue
		}
		add = append(add, lp.node)
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
