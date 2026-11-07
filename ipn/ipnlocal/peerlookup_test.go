// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/filter"
)

// peerLookupTest is a peerTokenTest whose self node may look up peers, with
// a fake lookup RPC.
type peerLookupTest struct {
	*peerTokenTest

	mu       sync.Mutex
	peers    []*tailcfg.Node // what control has
	err      error           // if non-nil, what every lookup fails with
	ttl      int             // TTLSeconds to respond with
	requests []tailcfg.PeerLookupRequest
	sinceTx  map[key.NodePublic]time.Duration // what sinceLastSendForTest returns
}

func newPeerLookupTest(t *testing.T) *peerLookupTest {
	lt := &peerLookupTest{peerTokenTest: newPeerTokenTest(t), ttl: 60}
	lt.selfName = "self.example.ts.net."
	lt.setNetMap(lt.selfCapMap(), nil)
	lt.b.peerLookupFuncForTest = lt.lookup
	lt.b.sinceLastSendForTest = func(nk key.NodePublic) (time.Duration, bool) {
		lt.mu.Lock()
		defer lt.mu.Unlock()
		d, ok := lt.sinceTx[nk]
		return d, ok
	}
	return lt
}

// selfCapMap is that of a peerTokenTest, plus the peer lookup capability.
func (lt *peerLookupTest) selfCapMap() tailcfg.NodeCapMap {
	m := lt.peerTokenTest.selfCapMap()
	m[nodecap.PeerLookup] = nil
	return m
}

func (lt *peerLookupTest) lookup(ctx context.Context, req *tailcfg.PeerLookupRequest) (*tailcfg.PeerLookupResponse, error) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.requests = append(lt.requests, *req)
	if lt.err != nil {
		return nil, lt.err
	}
	for _, n := range lt.peers {
		if (req.IP.IsValid() && n.Addresses[0].Addr() == req.IP) || (req.Name != "" && n.Name == req.Name+".") {
			return &tailcfg.PeerLookupResponse{Node: n.Clone(), TTLSeconds: lt.ttl}, nil
		}
	}
	return nil, errPeerLookupNotFound
}

func (lt *peerLookupTest) numRequests() int {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return len(lt.requests)
}

// addControlPeer makes control have the peer p, named name, with an
// endpoint and home DERP region, and returns it.
func (lt *peerLookupTest) addControlPeer(p tokenPeerIdentity, name string) *tailcfg.Node {
	n := &tailcfg.Node{
		ID:         p.id,
		StableID:   "stable",
		Name:       name,
		Key:        p.node,
		DiscoKey:   p.disco,
		Addresses:  []netip.Prefix{netip.PrefixFrom(p.ip, 32)},
		AllowedIPs: []netip.Prefix{netip.PrefixFrom(p.ip, 32)},
		Endpoints:  []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")},
		HomeDERP:   3,
	}
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.peers = append(lt.peers, n)
	return n
}

func (lt *peerLookupTest) setSentRecently(p tokenPeerIdentity, recently bool) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if recently {
		lt.sinceTx = map[key.NodePublic]time.Duration{p.node: time.Second}
	} else {
		lt.sinceTx = nil
	}
}

// waitFor waits for cond to be true, as async lookups and refreshes finish.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (lt *peerLookupTest) node(p tokenPeerIdentity) tailcfg.NodeView {
	lt.t.Helper()
	n, ok := lt.b.currentNode().NodeByID(p.id)
	if !ok {
		lt.t.Fatalf("node %d not present", p.id)
	}
	return n
}

func TestPeerLookupByIP(t *testing.T) {
	lt := newPeerLookupTest(t)
	b := lt.b
	p := newTokenPeerIdentity(100, "100.64.0.100")
	lt.addControlPeer(p, "peer.example.ts.net.")

	// The first packet finds no peer, but starts a lookup.
	if _, ok := b.lookupPeerByIP(p.ip); ok {
		t.Fatal("lookupPeerByIP found peer before lookup")
	}
	waitFor(t, "lookup", func() bool { return lt.present(p) })
	if got, ok := b.lookupPeerByIP(p.ip); !ok || got != p.node {
		t.Errorf("lookupPeerByIP = %v, %v; want %v", got, ok, p.node)
	}
	if req := lt.requests[0]; req.IP != p.ip || req.Name != "" || req.NodeKey != makeNodeKeyFromID(1) {
		t.Errorf("request = %+v", req)
	}

	n := lt.node(p)
	if n.Name() != "peer.example.ts.net." || n.HomeDERP() != 3 || n.Endpoints().Len() != 1 || n.DiscoKey() != p.disco {
		t.Errorf("bad node: %v", n.AsStruct())
	}
	cfg, ok := b.peerConfig(p.node)
	if !ok || len(cfg.AllowedIPs) != 1 || cfg.AllowedIPs[0] != netip.PrefixFrom(p.ip, 32) {
		t.Errorf("peerConfig = %v, %v", cfg, ok)
	}
	// We contact it, but it gets no access to us without a token.
	if got := lt.checkTCP22(p); got != filter.Drop {
		t.Errorf("filter port 22 = %v; want Drop", got)
	}

	// It's kept in full netmaps from control, which don't have it.
	lt.setNetMap(lt.selfCapMap(), nil)
	if !lt.present(p) {
		t.Error("looked-up peer dropped by new netmap")
	}

	// Addresses that aren't Tailscale IPs, or of quad-100, aren't looked up.
	for _, ip := range []string{"192.168.0.1", "100.100.100.100"} {
		b.lookupPeerByIP(netip.MustParseAddr(ip))
	}
	time.Sleep(10 * time.Millisecond)
	if got := lt.numRequests(); got != 1 {
		t.Errorf("requests = %d; want 1", got)
	}
}

func TestPeerLookupNotFound(t *testing.T) {
	lt := newPeerLookupTest(t)
	b := lt.b
	ip := netip.MustParseAddr("100.64.0.100")

	b.lookupPeerByIP(ip)
	waitFor(t, "lookup", func() bool { return lt.numRequests() == 1 })
	nb := b.currentNode()
	waitFor(t, "failure", func() bool {
		nb.mu.Lock()
		defer nb.mu.Unlock()
		return len(nb.peerLookupFailures) == 1
	})

	// More packets soon after don't look it up again.
	for range 10 {
		b.lookupPeerByIP(ip)
	}
	time.Sleep(10 * time.Millisecond)
	if got := lt.numRequests(); got != 1 {
		t.Fatalf("requests = %d; want 1", got)
	}

	// But later ones do.
	lt.clock.Advance(peerLookupFailureTTL)
	b.lookupPeerByIP(ip)
	waitFor(t, "second lookup", func() bool { return lt.numRequests() == 2 })
}

func TestPeerLookupUnavailable(t *testing.T) {
	lt := newPeerLookupTest(t)
	p := newTokenPeerIdentity(100, "100.64.0.100")
	lt.addControlPeer(p, "peer.example.ts.net.")
	lt.setNetMap(lt.peerTokenTest.selfCapMap(), nil) // without nodecap.PeerLookup

	lt.b.lookupPeerByIP(p.ip)
	if _, ok := (magicDNSHosts{lt.b}).LookupHost("peer.example.ts.net."); ok {
		t.Error("LookupHost found peer")
	}
	time.Sleep(10 * time.Millisecond)
	if got := lt.numRequests(); got != 0 {
		t.Errorf("requests = %d; want 0", got)
	}
}

func TestPeerLookupDNS(t *testing.T) {
	lt := newPeerLookupTest(t)
	p := newTokenPeerIdentity(100, "100.64.0.100")
	lt.addControlPeer(p, "peer.example.ts.net.")
	hosts := magicDNSHosts{lt.b}

	// Names outside our tailnet's domain, or not a single label in it,
	// aren't looked up.
	for _, name := range []dnsname.FQDN{"peer.other.ts.net.", "example.com.", "a.peer.example.ts.net.", "example.ts.net."} {
		if _, ok := hosts.LookupHost(name); ok {
			t.Errorf("LookupHost(%q) found something", name)
		}
	}
	if got := lt.numRequests(); got != 0 {
		t.Fatalf("requests = %d; want 0", got)
	}

	// Ours are, synchronously.
	ips, ok := hosts.LookupHost("Peer.Example.TS.net.")
	if !ok || len(ips) != 1 || ips[0] != p.ip {
		t.Fatalf("LookupHost = %v, %v; want [%v]", ips, ok, p.ip)
	}
	if req := lt.requests[0]; req.Name != "peer.example.ts.net" || req.IP.IsValid() {
		t.Errorf("request = %+v", req)
	}
	if !lt.present(p) {
		t.Error("peer not added")
	}

	// Names control doesn't have aren't found.
	if _, ok := hosts.LookupHost("nope.example.ts.net."); ok {
		t.Error("LookupHost(nope) found something")
	}
}

func TestPeerLookupBadResponse(t *testing.T) {
	lt := newPeerLookupTest(t)
	p := newTokenPeerIdentity(100, "100.64.0.100")
	n := lt.addControlPeer(p, "peer.example.ts.net.")
	n.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.101/32")} // not what we asked for
	n.AllowedIPs = n.Addresses

	if _, err := lt.b.lookupPeerWait(t.Context(), lt.b.currentNode(), peerLookupQuery{ip: p.ip}); err == nil {
		t.Fatal("lookup succeeded")
	}
	if _, ok := lt.b.currentNode().NodeByID(p.id); ok {
		t.Error("peer added")
	}
}

func TestPeerLookupExpiry(t *testing.T) {
	setup := func(t *testing.T) (*peerLookupTest, tokenPeerIdentity) {
		lt := newPeerLookupTest(t)
		p := newTokenPeerIdentity(100, "100.64.0.100")
		lt.addControlPeer(p, "peer.example.ts.net.")
		if _, err := lt.b.lookupPeerWait(t.Context(), lt.b.currentNode(), peerLookupQuery{ip: p.ip}); err != nil {
			t.Fatal(err)
		}
		return lt, p
	}
	ttl := 60 * time.Second

	t.Run("idle", func(t *testing.T) {
		lt, p := setup(t)
		lt.clock.Advance(ttl - time.Second)
		if !lt.present(p) {
			t.Fatal("peer gone before TTL")
		}
		lt.clock.Advance(time.Second)
		if lt.present(p) {
			t.Fatal("idle peer not removed at TTL")
		}
		if got := lt.numRequests(); got != 1 {
			t.Errorf("requests = %d; want 1", got)
		}
	})

	t.Run("active", func(t *testing.T) {
		lt, p := setup(t)
		lt.setSentRecently(p, true)
		lt.mu.Lock()
		lt.peers[0].HomeDERP = 9 // it moved
		lt.mu.Unlock()
		lt.clock.Advance(ttl)
		waitFor(t, "refresh", func() bool { return lt.node(p).HomeDERP() == 9 })

		// Once idle, it's removed at the next expiry.
		lt.setSentRecently(p, false)
		lt.clock.Advance(ttl)
		if lt.present(p) {
			t.Fatal("peer not removed once idle")
		}
	})

	t.Run("active_gone", func(t *testing.T) {
		lt, p := setup(t)
		lt.setSentRecently(p, true)
		lt.mu.Lock()
		lt.peers = nil
		lt.mu.Unlock()
		lt.clock.Advance(ttl)
		waitFor(t, "removal", func() bool { return !lt.present(p) })
	})

	t.Run("active_error", func(t *testing.T) {
		lt, p := setup(t)
		lt.setSentRecently(p, true)
		lt.mu.Lock()
		lt.err = errors.New("control unreachable")
		lt.mu.Unlock()
		lt.clock.Advance(ttl)
		waitFor(t, "refresh attempt", func() bool { return lt.numRequests() == 2 })
		// The stale result is kept, and retried later.
		nb := lt.b.currentNode()
		waitFor(t, "retry scheduled", func() bool {
			nb.mu.Lock()
			defer nb.mu.Unlock()
			lp := nb.localPeers[p.id]
			return lp != nil && lp.lookupExpiry.Equal(lt.clock.Now().Add(peerLookupRetryInterval))
		})
		if !lt.present(p) {
			t.Fatal("peer removed on refresh error")
		}
		lt.mu.Lock()
		lt.err = nil
		lt.mu.Unlock()
		lt.clock.Advance(peerLookupRetryInterval)
		waitFor(t, "retry", func() bool { return lt.numRequests() == 3 })
		if !lt.present(p) {
			t.Fatal("peer removed after successful retry")
		}
	})
}

func TestPeerLookupWithToken(t *testing.T) {
	t.Run("lookup_then_token", func(t *testing.T) {
		lt := newPeerLookupTest(t)
		b := lt.b
		p := newTokenPeerIdentity(100, "100.64.0.100")
		lt.addControlPeer(p, "peer.example.ts.net.")
		if _, err := b.lookupPeerWait(t.Context(), b.currentNode(), peerLookupQuery{ip: p.ip}); err != nil {
			t.Fatal(err)
		}

		// When the peer we looked up contacts us with its token, it gets
		// the token's access, and keeps what we looked up.
		b.handlePeerToken(viaDERP(p, lt.token(p, 2*time.Hour)))
		if got := lt.checkTCP22(p); got != filter.Accept {
			t.Errorf("filter port 22 = %v; want Accept", got)
		}
		n := lt.node(p)
		if n.Name() != "peer.example.ts.net." || n.HomeDERP() != 3 || !n.HasCap(testPeerCap) {
			t.Errorf("bad node: %v", n.AsStruct())
		}

		// The lookup result expiring leaves the token's peer.
		lt.clock.Advance(time.Minute)
		if !lt.present(p) {
			t.Fatal("peer removed with token still valid")
		}
		n = lt.node(p)
		if n.Name() != "" || !n.HasCap(testPeerCap) {
			t.Errorf("bad node after lookup expiry: %v", n.AsStruct())
		}
		lt.clock.Advance(2 * time.Hour)
		if lt.present(p) {
			t.Fatal("peer not removed after token expiry")
		}
	})

	t.Run("token_then_lookup", func(t *testing.T) {
		lt := newPeerLookupTest(t)
		b := lt.b
		p := newTokenPeerIdentity(100, "100.64.0.100")
		lt.addControlPeer(p, "peer.example.ts.net.")
		b.handlePeerToken(viaDERP(p, lt.token(p, 30*time.Second)))

		// A peer that contacted us with its token can be looked up, to get
		// its name and endpoints.
		ips, ok := magicDNSHosts{b}.LookupHost("peer.example.ts.net.")
		if !ok || len(ips) != 1 || ips[0] != p.ip {
			t.Fatalf("LookupHost = %v, %v", ips, ok)
		}
		n := lt.node(p)
		if n.Name() != "peer.example.ts.net." || !n.HasCap(testPeerCap) {
			t.Errorf("bad node: %v", n.AsStruct())
		}

		// The token expiring first leaves the lookup result, without access.
		lt.clock.Advance(30 * time.Second)
		if !lt.present(p) {
			t.Fatal("peer removed with lookup still valid")
		}
		if got := lt.checkTCP22(p); got != filter.Drop {
			t.Errorf("filter port 22 after token expiry = %v; want Drop", got)
		}
		if lt.node(p).HasCap(testPeerCap) {
			t.Error("peer has cap after token expiry")
		}
	})

	t.Run("key_change", func(t *testing.T) {
		lt := newPeerLookupTest(t)
		b := lt.b
		p := newTokenPeerIdentity(100, "100.64.0.100")
		b.handlePeerToken(viaDERP(p, lt.token(p, time.Hour)))

		// Control now has the peer with a new node key: the token, for its
		// old one, is forgotten.
		p2 := p
		p2.node = key.NewNode().Public()
		lt.addControlPeer(p2, "peer.example.ts.net.")
		if _, err := b.lookupPeerWait(t.Context(), b.currentNode(), peerLookupQuery{ip: p.ip}); err != nil {
			t.Fatal(err)
		}
		if n := lt.node(p); n.Key() != p2.node || n.HasCap(testPeerCap) {
			t.Errorf("bad node: %v", n.AsStruct())
		}
	})
}

func TestPeerLookupControlPeer(t *testing.T) {
	lt := newPeerLookupTest(t)
	p := newTokenPeerIdentity(100, "100.64.0.100")
	lt.addControlPeer(p, "peer.example.ts.net.")
	controlNode := (&tailcfg.Node{
		ID:        p.id,
		StableID:  "control",
		Key:       p.node,
		Addresses: []netip.Prefix{netip.PrefixFrom(p.ip, 32)},
	}).View()
	lt.setNetMap(lt.selfCapMap(), []tailcfg.NodeView{controlNode})

	// Looking up a peer control already sent us (perhaps from ping) changes
	// nothing.
	n, err := lt.b.lookupPeerWait(t.Context(), lt.b.currentNode(), peerLookupQuery{ip: p.ip})
	if err != nil {
		t.Fatal(err)
	}
	if !n.Equal(controlNode) || !lt.node(p).Equal(controlNode) {
		t.Errorf("got %v; want control's node", n.AsStruct())
	}
	if len(lt.b.currentNode().localPeers) != 0 {
		t.Error("control's peer recorded as local")
	}
}

func TestPeerLookupRateLimit(t *testing.T) {
	lt := newPeerLookupTest(t)
	nb := lt.b.currentNode()

	// A sweep of many IPs, none of which control has, is rate limited.
	for i := range 200 {
		ip := netip.AddrFrom4([4]byte{100, 64, 1, byte(i)})
		lt.b.lookupPeer(nb, peerLookupQuery{ip: ip})
	}
	if got := lt.numRequests(); got > peerLookupBurst+5 {
		t.Errorf("requests = %d; want about %d", got, peerLookupBurst)
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if got := len(nb.peerLookupFailures); got > maxPeerLookupFailures {
		t.Errorf("failures = %d; want <= %d", got, maxPeerLookupFailures)
	}
}
