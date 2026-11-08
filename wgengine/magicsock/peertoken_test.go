// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/disco"
	"tailscale.com/net/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
)

// sealDisco returns a disco packet carrying m from sender to the conn c.
func sealDisco(c *Conn, sender key.DiscoPrivate, m disco.Message) []byte {
	pkt := []byte(disco.Magic)
	pkt = sender.Public().AppendTo(pkt)
	return append(pkt, sender.Shared(c.discoAtomic.Public()).Seal(m.AppendMarshal(nil))...)
}

func newPeerTokenTestConn(t *testing.T) (*Conn, chan PeerTokenMessage) {
	c := newConn(t.Logf)
	c.privateKey = key.NewNode()
	got := make(chan PeerTokenMessage, 100)
	c.SetPeerTokenHandler(func(m PeerTokenMessage) { got <- m })
	return c, got
}

func TestPeerTokenFromUnknownSender(t *testing.T) {
	c, got := newPeerTokenTestConn(t)
	sender := key.NewDisco()
	senderNode := key.NewNode().Public()
	derpSrc := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 7)}

	c.handleDiscoMessage(sealDisco(c, sender, &disco.PeerToken{Token: []byte("a.b.c")}), derpSrc, false, senderNode, discoRXPathDERP)
	select {
	case m := <-got:
		want := PeerTokenMessage{Token: "a.b.c", DiscoKey: sender.Public(), DERPNodeKey: senderNode, DERPRegion: 7}
		if m != want {
			t.Errorf("got %+v; want %+v", m, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler not called")
	}

	udpSrc := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:41641")}
	c.handleDiscoMessage(sealDisco(c, sender, &disco.PeerToken{Token: []byte("d.e.f")}), udpSrc, false, key.NodePublic{}, discoRXPathUDP)
	select {
	case m := <-got:
		want := PeerTokenMessage{Token: "d.e.f", DiscoKey: sender.Public(), UDPSrc: udpSrc.ap}
		if m != want {
			t.Errorf("got %+v; want %+v", m, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler not called")
	}

	// The unauthenticated sender's shared key wasn't cached.
	c.mu.Lock()
	n := len(c.discoInfo)
	c.mu.Unlock()
	if n != 0 {
		t.Errorf("discoInfo has %d entries; want 0", n)
	}
}

func TestPeerTokenUnknownSenderOtherMessagesDropped(t *testing.T) {
	c, got := newPeerTokenTestConn(t)
	sender := key.NewDisco()
	derpSrc := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 7)}

	c.handleDiscoMessage(sealDisco(c, sender, &disco.Ping{}), derpSrc, false, key.NewNode().Public(), discoRXPathDERP)
	c.handleDiscoMessage(sealDisco(c, sender, &disco.CallMeMaybe{}), derpSrc, false, key.NewNode().Public(), discoRXPathDERP)

	// Sealed for some other recipient.
	other := newConn(t.Logf)
	c.handleDiscoMessage(sealDisco(other, sender, &disco.PeerToken{Token: []byte("a.b.c")}), derpSrc, false, key.NewNode().Public(), discoRXPathDERP)

	// Without a handler, even PeerTokens are dropped.
	c.SetPeerTokenHandler(nil)
	c.handleDiscoMessage(sealDisco(c, sender, &disco.PeerToken{Token: []byte("a.b.c")}), derpSrc, false, key.NewNode().Public(), discoRXPathDERP)

	select {
	case m := <-got:
		t.Fatalf("handler unexpectedly called with %+v", m)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPeerTokenRateLimited(t *testing.T) {
	c, got := newPeerTokenTestConn(t)
	derpSrc := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 7)}
	const sent = peerTokenBurst * 2
	for range sent {
		c.handleDiscoMessage(sealDisco(c, key.NewDisco(), &disco.PeerToken{Token: []byte("a.b.c")}), derpSrc, false, key.NewNode().Public(), discoRXPathDERP)
	}
	// Allow for a few tokens refilling while the loop runs.
	time.Sleep(100 * time.Millisecond)
	if n := len(got); n < peerTokenBurst || n >= sent {
		t.Errorf("handler called %d times for %d messages; want about %d", n, sent, peerTokenBurst)
	}
}

func TestSetSelfPeerToken(t *testing.T) {
	c := newConn(t.Logf)
	set := func(token string) *selfPeerToken {
		c.SetSelfPeerToken(token)
		return c.selfPeerToken.Load()
	}
	if got := set(""); got != nil {
		t.Fatalf("empty: got %q", got.token)
	}
	t1 := set("a.b.c")
	if t1 == nil || string(t1.token) != "a.b.c" {
		t.Fatalf("got %v; want a.b.c", t1)
	}
	if got := set("a.b.c"); got != t1 {
		t.Error("unchanged token: pointer changed")
	}
	t2 := set("d.e.f")
	if t2 == t1 || string(t2.token) != "d.e.f" {
		t.Errorf("changed token: got %v", t2)
	}
	if got := set(strings.Repeat("x", disco.MaxPeerTokenLen+1)); got != nil {
		t.Errorf("too long: got %d bytes", len(got.token))
	}
	set("a.b.c")
	if got := set(""); got != nil {
		t.Errorf("cleared: got %q", got.token)
	}
}

func TestMaybeSendPeerToken(t *testing.T) {
	c := newConn(t.Logf)
	de := &endpoint{c: c, publicKey: key.NewNode().Public()}
	epDisco := &endpointDisco{controlKey: key.NewDisco().Public()}
	tok := &selfPeerToken{token: []byte("a.b.c")}

	now := mono.Now()
	// sent reports whether maybeSendPeerTokenLocked decided to send at t.
	sent := func(at mono.Time) bool {
		de.mu.Lock()
		defer de.mu.Unlock()
		before := de.peerTokenSentAt
		de.maybeSendPeerTokenLocked(at, epDisco)
		return de.peerTokenSentAt != before
	}

	if sent(now) {
		t.Fatal("sent without a token")
	}
	c.selfPeerToken.Store(tok)
	if !sent(now) {
		t.Fatal("first contact: not sent")
	}
	if sent(now.Add(time.Second)) {
		t.Error("resent immediately")
	}
	// Having heard from the peer recently, don't resend.
	de.lastRecvWG.StoreAtomic(now.Add(peerTokenResendInterval))
	if sent(now.Add(peerTokenResendInterval + time.Second)) {
		t.Error("resent to a peer we hear from")
	}
	// After a silence, resend: the peer may have forgotten us.
	later := now.Add(3 * peerTokenResendInterval)
	if !sent(later) {
		t.Error("not resent after silence")
	}
	// A new token is sent right away.
	c.selfPeerToken.Store(&selfPeerToken{token: []byte("d.e.f")})
	if !sent(later.Add(time.Second)) {
		t.Error("new token not sent")
	}
	// As it is after an endpoint reset (such as a disco key change).
	de.mu.Lock()
	de.invalidateDiscoPathLocked()
	de.mu.Unlock()
	if !sent(later.Add(2 * time.Second)) {
		t.Error("not sent after reset")
	}
}

// TestPeerTokenSentOnContact checks that a node with a peer token presents
// it, when it initiates contact, to a peer whose netmap doesn't include it.
func TestPeerTokenSentOnContact(t *testing.T) {
	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	m1 := newMagicStack(t, logger.WithPrefix(t.Logf, "conn1: "), localhostListener{}, derpMap)
	defer m1.Close()
	m2 := newMagicStack(t, logger.WithPrefix(t.Logf, "conn2: "), localhostListener{}, derpMap)
	defer m2.Close()

	got := make(chan PeerTokenMessage, 100)
	m2.conn.SetPeerTokenHandler(func(m PeerTokenMessage) { got <- m })

	const token = "a.b.c"
	cleanupMesh := meshStacks(t.Logf, func(idx int, nm *netmap.NetworkMap) {
		switch idx {
		case 1:
			nm.Peers = nil // m2 doesn't know m1
		}
	}, m1, m2)
	defer cleanupMesh()
	m1.conn.SetSelfPeerToken(token)

	m1.tun.Outbound <- tuntest.Ping(m2.IP(), m1.IP())

	select {
	case m := <-got:
		if m.Token != token {
			t.Errorf("token = %q; want %q", m.Token, token)
		}
		if m.DiscoKey != m1.conn.DiscoPublicKey() {
			t.Errorf("disco key = %v; want %v", m.DiscoKey, m1.conn.DiscoPublicKey())
		}
		if !m.DERPNodeKey.IsZero() && m.DERPNodeKey != m1.Public() {
			t.Errorf("DERP node key = %v; want %v", m.DERPNodeKey, m1.Public())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("peer token not received")
	}
}

// TestPresentPeerToken checks that PresentPeerToken sends our peer token to
// a peer without waiting for disco pings, and only once in a while.
func TestPresentPeerToken(t *testing.T) {
	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	m1 := newMagicStack(t, logger.WithPrefix(t.Logf, "conn1: "), localhostListener{}, derpMap)
	defer m1.Close()
	m2 := newMagicStack(t, logger.WithPrefix(t.Logf, "conn2: "), localhostListener{}, derpMap)
	defer m2.Close()

	got := make(chan PeerTokenMessage, 100)
	m2.conn.SetPeerTokenHandler(func(m PeerTokenMessage) { got <- m })

	const token = "a.b.c"
	cleanupMesh := meshStacks(t.Logf, func(idx int, nm *netmap.NetworkMap) {
		switch idx {
		case 1:
			nm.Peers = nil // m2 doesn't know m1
		}
	}, m1, m2)
	defer cleanupMesh()
	m1.conn.SetSelfPeerToken(token)

	// Wait for m1 to know m2, with its disco key.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		m1.conn.mu.Lock()
		de, ok := m1.conn.peerMap.endpointForNodeKey(m2.Public())
		m1.conn.mu.Unlock()
		if ok && de.disco.Load() != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("m1 doesn't know m2")
		}
	}

	m1.conn.PresentPeerToken(m2.Public())
	select {
	case m := <-got:
		if m.Token != token {
			t.Errorf("token = %q; want %q", m.Token, token)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("peer token not received")
	}
	// One presentation may arrive both via DERP and directly.
	drain := func() (n int) {
		for {
			select {
			case <-got:
				n++
			case <-time.After(time.Second):
				return n
			}
		}
	}
	drain()

	// Presenting it again right away doesn't resend it.
	m1.conn.PresentPeerToken(m2.Public())
	if n := drain(); n != 0 {
		t.Errorf("token resent %d times", n)
	}

	// Unknown peers are ignored.
	m1.conn.PresentPeerToken(key.NewNode().Public())
}

// TestRenewedPeerTokenPresented checks that a new self peer token is
// presented right away to the peers we've exchanged traffic with since we
// last presented them one, but not to idle ones.
func TestRenewedPeerTokenPresented(t *testing.T) {
	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	m1 := newMagicStack(t, logger.WithPrefix(t.Logf, "conn1: "), localhostListener{}, derpMap)
	defer m1.Close()
	m2 := newMagicStack(t, logger.WithPrefix(t.Logf, "conn2: "), localhostListener{}, derpMap)
	defer m2.Close()

	got := make(chan PeerTokenMessage, 100)
	m2.conn.SetPeerTokenHandler(func(m PeerTokenMessage) { got <- m })
	cleanupMesh := meshStacks(t.Logf, func(idx int, nm *netmap.NetworkMap) {
		if idx == 1 {
			nm.Peers = nil // m2 doesn't know m1
		}
	}, m1, m2)
	defer cleanupMesh()

	var de *endpoint
	for deadline := time.Now().Add(10 * time.Second); de == nil || de.disco.Load() == nil; time.Sleep(10 * time.Millisecond) {
		m1.conn.mu.Lock()
		de, _ = m1.conn.peerMap.endpointForNodeKey(m2.Public())
		m1.conn.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("m1 doesn't know m2")
		}
	}
	// tokens returns the distinct tokens m2 receives within a second.
	tokens := func() (toks []string) {
		for {
			select {
			case m := <-got:
				if !slices.Contains(toks, m.Token) {
					toks = append(toks, m.Token)
				}
			case <-time.After(time.Second):
				return toks
			}
		}
	}

	m1.conn.SetSelfPeerToken("a.b.c")
	m1.conn.PresentPeerToken(m2.Public())
	if toks := tokens(); !slices.Equal(toks, []string{"a.b.c"}) {
		t.Fatalf("initial tokens = %q", toks)
	}

	// Idle since: the renewed token isn't presented.
	m1.conn.SetSelfPeerToken("d.e.f")
	if toks := tokens(); len(toks) != 0 {
		t.Errorf("idle peer got tokens %q", toks)
	}

	// After traffic, it is.
	de.lastRecvWG.StoreAtomic(mono.Now())
	m1.conn.SetSelfPeerToken("g.h.i")
	if toks := tokens(); !slices.Equal(toks, []string{"g.h.i"}) {
		t.Errorf("active peer got tokens %q; want [g.h.i]", toks)
	}
}
