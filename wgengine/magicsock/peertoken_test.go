// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/disco"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
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
