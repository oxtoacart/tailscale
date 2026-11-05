// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
)

const testPeerCap = "example.com/cap/widget"

type peerTokenTest struct {
	t       *testing.T
	b       *LocalBackend
	clock   *tstest.Clock
	signKey ed25519.PrivateKey
	selfIP  netip.Addr
}

func newPeerTokenTest(t *testing.T) *peerTokenTest {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := newTestLocalBackend(t)
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(1_800_000_000, 0)})
	b.clock = clock
	pt := &peerTokenTest{
		t:       t,
		b:       b,
		clock:   clock,
		signKey: priv,
		selfIP:  netip.MustParseAddr("100.64.0.1"),
	}
	pt.setNetMap(pt.selfCapMap(), nil)
	return pt
}

func (pt *peerTokenTest) jwk() tailcfg.RawMessage {
	return tailcfg.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"k1","x":%q}`,
		base64.RawURLEncoding.EncodeToString(pt.signKey.Public().(ed25519.PublicKey))))
}

// selfCapMap returns a self CapMap trusting pt's signing key and granting
// token peers with testPeerCap access to TCP port 22 on self.
func (pt *peerTokenTest) selfCapMap() tailcfg.NodeCapMap {
	return tailcfg.NodeCapMap{
		nodecap.PeerTokenKeys: {pt.jwk()},
		"cap:" + testPeerCap: {tailcfg.RawMessage(fmt.Sprintf(
			`{"SrcIPs":["*"],"DstPorts":[{"IP":%q,"Ports":{"First":22,"Last":22}}]}`, pt.selfIP))},
	}
}

func (pt *peerTokenTest) setNetMap(selfCaps tailcfg.NodeCapMap, peers []tailcfg.NodeView) {
	self := &tailcfg.Node{
		ID:        1,
		StableID:  "self",
		Key:       makeNodeKeyFromID(1),
		Addresses: []netip.Prefix{netip.PrefixFrom(pt.selfIP, 32)},
		CapMap:    selfCaps,
	}
	nm := &netmap.NetworkMap{
		SelfNode: self.View(),
		NodeKey:  self.Key,
		Peers:    peers,
	}
	b := pt.b
	b.mu.Lock()
	defer b.mu.Unlock()
	b.setNetMapLocked(nm)
	prefs := ipn.NewPrefs()
	prefs.ShieldsUp = false
	b.updateFilterLocked(prefs.View())
}

type tokenPeerIdentity struct {
	id    tailcfg.NodeID
	node  key.NodePublic
	disco key.DiscoPublic
	ip    netip.Addr
}

func newTokenPeerIdentity(id tailcfg.NodeID, ip string) tokenPeerIdentity {
	return tokenPeerIdentity{
		id:    id,
		node:  key.NewNode().Public(),
		disco: key.NewDisco().Public(),
		ip:    netip.MustParseAddr(ip),
	}
}

func (pt *peerTokenTest) token(p tokenPeerIdentity, ttl time.Duration, mutate ...func(map[string]any)) string {
	claims := map[string]any{
		"exp":       pt.clock.Now().Add(ttl).Unix(),
		"node_id":   p.id,
		"node_key":  p.node,
		"disco_key": p.disco,
		"addresses": []netip.Prefix{netip.PrefixFrom(p.ip, 32)},
		"cap":       "cap:" + testPeerCap,
	}
	for _, f := range mutate {
		f(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		pt.t.Fatal(err)
	}
	in := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`)) +
		"." + base64.RawURLEncoding.EncodeToString(payload)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(pt.signKey, []byte(in)))
}

// viaDERP returns a message carrying token as received over DERP from p.
func viaDERP(p tokenPeerIdentity, token string) magicsock.PeerTokenMessage {
	return magicsock.PeerTokenMessage{
		Token:       token,
		DiscoKey:    p.disco,
		DERPNodeKey: p.node,
		DERPRegion:  7,
	}
}

func (pt *peerTokenTest) present(p tokenPeerIdentity) bool {
	pt.t.Helper()
	cn := pt.b.currentNode()
	id, ok := cn.NodeByKey(p.node)
	if !ok {
		return false
	}
	if id != p.id {
		pt.t.Fatalf("NodeByKey = %v; want %v", id, p.id)
	}
	return true
}

func (pt *peerTokenTest) checkTCP22(p tokenPeerIdentity) filter.Response {
	return pt.b.currentNode().filter().CheckTCP(p.ip, pt.selfIP, 22)
}

func TestPeerTokenAccept(t *testing.T) {
	pt := newPeerTokenTest(t)
	b := pt.b
	p := newTokenPeerIdentity(100, "100.64.0.100")

	if got := pt.checkTCP22(p); got != filter.Drop {
		t.Fatalf("before token: filter = %v; want Drop", got)
	}

	b.handlePeerToken(viaDERP(p, pt.token(p, time.Hour)))
	if !pt.present(p) {
		t.Fatal("token peer not added")
	}

	n, ok := b.currentNode().NodeByID(p.id)
	if !ok {
		t.Fatal("NodeByID failed")
	}
	if n.DiscoKey() != p.disco || n.HomeDERP() != 7 || !n.HasCap(testPeerCap) {
		t.Errorf("bad synthesized node: %v", n.AsStruct())
	}

	// WireGuard would lazily create the peer with exactly its token address.
	cfg, ok := b.peerConfig(p.node)
	if !ok || len(cfg.AllowedIPs) != 1 || cfg.AllowedIPs[0] != netip.PrefixFrom(p.ip, 32) {
		t.Errorf("peerConfig = %v, %v; want AllowedIPs [%v/32]", cfg, ok, p.ip)
	}
	if got, ok := b.lookupPeerByIP(p.ip); !ok || got != p.node {
		t.Errorf("lookupPeerByIP = %v, %v", got, ok)
	}

	// The self CapMap's "cap:..." rule applies to it, and only to port 22.
	if !b.srcIPHasCapForFilter(p.ip, testPeerCap) {
		t.Error("srcIPHasCapForFilter = false")
	}
	if got := pt.checkTCP22(p); got != filter.Accept {
		t.Errorf("filter port 22 = %v; want Accept", got)
	}
	if got := b.currentNode().filter().CheckTCP(p.ip, pt.selfIP, 80); got != filter.Drop {
		t.Errorf("filter port 80 = %v; want Drop", got)
	}
	// The rule's control-supplied SrcIPs "*" was not honored.
	other := netip.MustParseAddr("100.64.0.200")
	if got := b.currentNode().filter().CheckTCP(other, pt.selfIP, 22); got != filter.Drop {
		t.Errorf("filter from non-token IP = %v; want Drop", got)
	}
}

func TestPeerTokenReject(t *testing.T) {
	controlPeer := (&tailcfg.Node{
		ID:        50,
		StableID:  "control50",
		Key:       makeNodeKeyFromID(50),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.50/32")},
	}).View()

	tests := []struct {
		name string
		msg  func(pt *peerTokenTest, p tokenPeerIdentity) magicsock.PeerTokenMessage
	}{
		{"wrong_disco_key", func(pt *peerTokenTest, p tokenPeerIdentity) magicsock.PeerTokenMessage {
			m := viaDERP(p, pt.token(p, time.Hour))
			m.DiscoKey = key.NewDisco().Public()
			return m
		}},
		{"wrong_derp_node_key", func(pt *peerTokenTest, p tokenPeerIdentity) magicsock.PeerTokenMessage {
			m := viaDERP(p, pt.token(p, time.Hour))
			m.DERPNodeKey = key.NewNode().Public()
			return m
		}},
		{"expired", func(pt *peerTokenTest, p tokenPeerIdentity) magicsock.PeerTokenMessage {
			return viaDERP(p, pt.token(p, -time.Second))
		}},
		{"cap_not_granted_to_self", func(pt *peerTokenTest, p tokenPeerIdentity) magicsock.PeerTokenMessage {
			return viaDERP(p, pt.token(p, time.Hour, func(c map[string]any) { c["cap"] = "cap:example.com/cap/other" }))
		}},
		{"address_of_control_peer", func(pt *peerTokenTest, p tokenPeerIdentity) magicsock.PeerTokenMessage {
			return viaDERP(p, pt.token(p, time.Hour, func(c map[string]any) { c["addresses"] = []string{"100.64.0.50/32"} }))
		}},
		{"address_of_self", func(pt *peerTokenTest, p tokenPeerIdentity) magicsock.PeerTokenMessage {
			return viaDERP(p, pt.token(p, time.Hour, func(c map[string]any) { c["addresses"] = []string{"100.64.0.1/32"} }))
		}},
		{"node_id_of_control_peer", func(pt *peerTokenTest, p tokenPeerIdentity) magicsock.PeerTokenMessage {
			return viaDERP(p, pt.token(p, time.Hour, func(c map[string]any) { c["node_id"] = 50 }))
		}},
		{"node_id_of_self", func(pt *peerTokenTest, p tokenPeerIdentity) magicsock.PeerTokenMessage {
			return viaDERP(p, pt.token(p, time.Hour, func(c map[string]any) { c["node_id"] = 1 }))
		}},
		{"untrusted_signer", func(pt *peerTokenTest, p tokenPeerIdentity) magicsock.PeerTokenMessage {
			// Sign with a key that's not in the self CapMap (but
			// uses the same key ID).
			_, pt.signKey, _ = ed25519.GenerateKey(rand.Reader)
			return viaDERP(p, pt.token(p, time.Hour))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pt := newPeerTokenTest(t)
			pt.setNetMap(pt.selfCapMap(), []tailcfg.NodeView{controlPeer})
			p := newTokenPeerIdentity(100, "100.64.0.100")
			pt.b.handlePeerToken(tt.msg(pt, p))
			if pt.present(p) {
				t.Fatal("token peer was added; want rejected")
			}
			if n, ok := pt.b.currentNode().NodeByID(50); !ok || n.Key() != controlPeer.Key() {
				t.Fatal("control peer was clobbered")
			}
		})
	}

	t.Run("no_signing_keys", func(t *testing.T) {
		pt := newPeerTokenTest(t)
		caps := pt.selfCapMap()
		delete(caps, nodecap.PeerTokenKeys)
		pt.setNetMap(caps, nil)
		p := newTokenPeerIdentity(100, "100.64.0.100")
		pt.b.handlePeerToken(viaDERP(p, pt.token(p, time.Hour)))
		if pt.present(p) {
			t.Fatal("token peer was added without trusted signing keys")
		}
	})

	t.Run("tailnet_lock", func(t *testing.T) {
		pt := newPeerTokenTest(t)
		pt.b.mu.Lock()
		pt.b.tka = &tkaState{}
		pt.b.mu.Unlock()
		p := newTokenPeerIdentity(100, "100.64.0.100")
		pt.b.handlePeerToken(viaDERP(p, pt.token(p, time.Hour)))
		pt.b.mu.Lock()
		pt.b.tka = nil
		pt.b.mu.Unlock()
		if pt.present(p) {
			t.Fatal("token peer was added with tailnet lock enabled")
		}
	})
}

func TestPeerTokenExpiryAndRenewal(t *testing.T) {
	pt := newPeerTokenTest(t)
	b := pt.b
	p := newTokenPeerIdentity(100, "100.64.0.100")

	b.handlePeerToken(viaDERP(p, pt.token(p, time.Hour)))
	if !pt.present(p) {
		t.Fatal("token peer not added")
	}

	// Renew over UDP 30 minutes in, for another hour.
	pt.clock.Advance(30 * time.Minute)
	b.handlePeerToken(magicsock.PeerTokenMessage{
		Token:    pt.token(p, time.Hour),
		DiscoKey: p.disco,
		UDPSrc:   netip.MustParseAddrPort("192.0.2.1:41641"),
	})
	n, _ := b.currentNode().NodeByID(p.id)
	if n.HomeDERP() != 7 {
		t.Errorf("HomeDERP = %v after UDP renewal; want 7 carried forward", n.HomeDERP())
	}
	if n.Endpoints().Len() != 1 {
		t.Errorf("Endpoints = %v; want the UDP source", n.Endpoints())
	}

	// A replay of an older token doesn't shorten it.
	b.handlePeerToken(viaDERP(p, pt.token(p, time.Minute)))

	// Past the first token's expiry: still present.
	pt.clock.Advance(45 * time.Minute)
	if !pt.present(p) {
		t.Fatal("token peer removed at original expiry despite renewal")
	}
	if got := pt.checkTCP22(p); got != filter.Accept {
		t.Errorf("filter = %v; want Accept", got)
	}

	// Past the renewed expiry: gone.
	pt.clock.Advance(20 * time.Minute)
	if pt.present(p) {
		t.Fatal("token peer still present after expiry")
	}
	if got := pt.checkTCP22(p); got != filter.Drop {
		t.Errorf("filter after expiry = %v; want Drop", got)
	}
	if _, ok := b.peerConfig(p.node); ok {
		t.Error("peerConfig still knows expired peer")
	}
}

func TestPeerTokenFullNetmap(t *testing.T) {
	t.Run("survives_netmap", func(t *testing.T) {
		pt := newPeerTokenTest(t)
		p := newTokenPeerIdentity(100, "100.64.0.100")
		pt.b.handlePeerToken(viaDERP(p, pt.token(p, time.Hour)))
		pt.setNetMap(pt.selfCapMap(), nil)
		if !pt.present(p) {
			t.Fatal("token peer lost across full netmap")
		}
		// Reinstalling the current (merged) netmap doesn't duplicate it.
		pt.b.DebugForceNetmapUpdate()
		if got := len(pt.b.currentNode().Peers()); got != 1 {
			t.Fatalf("got %d peers; want 1", got)
		}
		if !pt.present(p) {
			t.Fatal("token peer lost across netmap reinstall")
		}
	})

	t.Run("cap_revoked", func(t *testing.T) {
		pt := newPeerTokenTest(t)
		p := newTokenPeerIdentity(100, "100.64.0.100")
		pt.b.handlePeerToken(viaDERP(p, pt.token(p, time.Hour)))
		caps := pt.selfCapMap()
		delete(caps, "cap:"+testPeerCap)
		pt.setNetMap(caps, nil)
		if pt.present(p) {
			t.Fatal("token peer kept after control revoked the cap")
		}
	})

	t.Run("signing_key_revoked", func(t *testing.T) {
		pt := newPeerTokenTest(t)
		p := newTokenPeerIdentity(100, "100.64.0.100")
		pt.b.handlePeerToken(viaDERP(p, pt.token(p, time.Hour)))
		caps := pt.selfCapMap()
		delete(caps, nodecap.PeerTokenKeys)
		pt.setNetMap(caps, nil)
		if pt.present(p) {
			t.Fatal("token peer kept after control revoked the signing key")
		}
	})

	t.Run("control_takes_over", func(t *testing.T) {
		pt := newPeerTokenTest(t)
		p := newTokenPeerIdentity(100, "100.64.0.100")
		pt.b.handlePeerToken(viaDERP(p, pt.token(p, time.Hour)))
		fromControl := (&tailcfg.Node{
			ID:        p.id,
			StableID:  "fromcontrol",
			Key:       p.node,
			DiscoKey:  p.disco,
			Addresses: []netip.Prefix{netip.PrefixFrom(p.ip, 32)},
		}).View()
		pt.setNetMap(pt.selfCapMap(), []tailcfg.NodeView{fromControl})
		// The token's expiry must not remove the control-managed peer.
		pt.clock.Advance(2 * time.Hour)
		n, ok := pt.b.currentNode().NodeByID(p.id)
		if !ok || n.StableID() != "fromcontrol" {
			t.Fatalf("control peer missing or replaced after token expiry: %v, %v", n, ok)
		}
	})

	t.Run("control_delta_takes_over", func(t *testing.T) {
		pt := newPeerTokenTest(t)
		p := newTokenPeerIdentity(100, "100.64.0.100")
		pt.b.handlePeerToken(viaDERP(p, pt.token(p, time.Hour)))
		fromControl := (&tailcfg.Node{
			ID:        p.id,
			StableID:  "fromcontrol",
			Key:       p.node,
			DiscoKey:  p.disco,
			Addresses: []netip.Prefix{netip.PrefixFrom(p.ip, 32)},
		}).View()
		pt.b.UpdateNetmapDelta([]netmap.NodeMutation{netmap.NodeMutationUpsert{Node: fromControl}})
		pt.clock.Advance(2 * time.Hour)
		n, ok := pt.b.currentNode().NodeByID(p.id)
		if !ok || n.StableID() != "fromcontrol" {
			t.Fatalf("control peer missing or replaced after token expiry: %v, %v", n, ok)
		}
	})

	t.Run("control_patch_still_expires", func(t *testing.T) {
		pt := newPeerTokenTest(t)
		p := newTokenPeerIdentity(100, "100.64.0.100")
		pt.b.handlePeerToken(viaDERP(p, pt.token(p, time.Hour)))
		muts, ok := netmap.MutationsFromMapResponse(&tailcfg.MapResponse{
			PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: p.id, Online: new(true)}},
		}, pt.clock.Now())
		if !ok {
			t.Fatal("MutationsFromMapResponse failed")
		}
		pt.b.UpdateNetmapDelta(muts)
		pt.clock.Advance(2 * time.Hour)
		if pt.present(p) {
			t.Fatal("patched token peer not removed at expiry")
		}
	})

	t.Run("not_cached", func(t *testing.T) {
		pt := newPeerTokenTest(t)
		p := newTokenPeerIdentity(100, "100.64.0.100")
		pt.b.handlePeerToken(viaDERP(p, pt.token(p, time.Hour)))
		pt.b.mu.Lock()
		got := pt.b.mergeTokenPeersLocked(nil)
		pt.b.mu.Unlock()
		if got != nil {
			t.Fatal("merge of nil netmap is non-nil")
		}
		if len(pt.b.currentNode().tokenPeers) != 0 {
			t.Fatal("token peers not forgotten when netmap cleared")
		}
	})
}
