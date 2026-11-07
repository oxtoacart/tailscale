// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package peertoken

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

var testNow = time.Unix(1_800_000_000, 0)

type testSigner struct {
	kid  string
	priv ed25519.PrivateKey
}

func newTestSigner(t testing.TB, kid string) *testSigner {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{kid: kid, priv: priv}
}

func (s *testSigner) jwk() tailcfg.RawMessage {
	return tailcfg.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":%q,"x":%q}`,
		s.kid, base64.RawURLEncoding.EncodeToString(s.priv.Public().(ed25519.PublicKey))))
}

func (s *testSigner) keySet(t testing.TB) KeySet {
	ks, err := KeySetFromSelfCapMap(views.MapSliceOf(tailcfg.NodeCapMap{
		nodecap.PeerTokenKeys: {s.jwk()},
	}))
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// sign signs claims (an arbitrary JSON-able value) with go-jose, to check
// interoperability with a standard JWT implementation.
func (s *testSigner) sign(t testing.TB, claims any) string {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       jose.JSONWebKey{Key: s.priv, KeyID: s.kid},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func validClaims() map[string]any {
	return map[string]any{
		"iss":       "https://controlplane.example",
		"sub":       "nStable1",
		"exp":       testNow.Add(time.Hour).Unix(),
		"iat":       testNow.Unix(),
		"node_id":   123,
		"node_key":  key.NewNode().Public(),
		"disco_key": key.NewDisco().Public(),
		"addresses": []string{"100.64.1.2/32", "fd7a:115c:a1e0::1:2/128"},
		"caps":      []string{"cap:example.com/cap/widget", "cap:example.com/cap/gadget"},
	}
}

func TestVerify(t *testing.T) {
	s := newTestSigner(t, "k1")
	ks := s.keySet(t)

	c := validClaims()
	got, err := Verify(s.sign(t, c), ks, testNow)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.NodeID != 123 || got.NodeKey != c["node_key"] || got.DiscoKey != c["disco_key"] {
		t.Errorf("wrong identity claims: %+v", got)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("100.64.1.2/32"), netip.MustParsePrefix("fd7a:115c:a1e0::1:2/128")}; fmt.Sprint(got.Addresses) != fmt.Sprint(want) {
		t.Errorf("Addresses = %v; want %v", got.Addresses, want)
	}
	if !got.Expiry.Equal(testNow.Add(time.Hour)) {
		t.Errorf("Expiry = %v", got.Expiry)
	}
	if want := []string{"cap:example.com/cap/widget", "cap:example.com/cap/gadget"}; !slices.Equal(got.Caps, want) {
		t.Errorf("Caps = %q; want %q", got.Caps, want)
	}
	if got.Subject != "nStable1" {
		t.Errorf("Subject = %q", got.Subject)
	}
}

func TestVerifyRejects(t *testing.T) {
	s := newTestSigner(t, "k1")
	ks := s.keySet(t)

	with := func(k string, v any) map[string]any {
		c := validClaims()
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	tests := []struct {
		name    string
		token   func() string
		wantErr string
	}{
		{"expired", func() string { return s.sign(t, with("exp", testNow.Unix())) }, "expired"},
		{"no_exp", func() string { return s.sign(t, with("exp", nil)) }, "missing exp"},
		{"not_yet_valid", func() string { return s.sign(t, with("nbf", testNow.Add(2*time.Minute).Unix())) }, "not valid until"},
		{"issued_in_future", func() string { return s.sign(t, with("iat", testNow.Add(2*time.Minute).Unix())) }, "future"},
		{"no_node_id", func() string { return s.sign(t, with("node_id", nil)) }, "node_id"},
		{"no_node_key", func() string { return s.sign(t, with("node_key", nil)) }, "node_key"},
		{"no_disco_key", func() string { return s.sign(t, with("disco_key", nil)) }, "disco_key"},
		{"no_addresses", func() string { return s.sign(t, with("addresses", nil)) }, "addresses"},
		{"non_tailscale_addr", func() string { return s.sign(t, with("addresses", []string{"10.0.0.1/32"})) }, "invalid address"},
		{"subnet_addr", func() string { return s.sign(t, with("addresses", []string{"100.64.0.0/24"})) }, "invalid address"},
		{"no_caps", func() string { return s.sign(t, with("caps", nil)) }, "missing caps"},
		{"empty_caps", func() string { return s.sign(t, with("caps", []string{})) }, "missing caps"},
		{"caps_not_list", func() string { return s.sign(t, with("caps", "cap:example.com/cap/widget")) }, "parsing claims"},
		{"cap_no_prefix", func() string {
			return s.sign(t, with("caps", []string{"cap:example.com/cap/widget", "example.com/cap/gadget"}))
		}, "invalid cap"},
		{"cap_empty", func() string { return s.sign(t, with("caps", []string{"cap:"})) }, "invalid cap"},
		{"bad_name", func() string { return s.sign(t, with("name", "not a name!")) }, "invalid name"},
		{"unknown_kid", func() string { return newTestSigner(t, "other").sign(t, validClaims()) }, "unknown signing key"},
		{"wrong_key_same_kid", func() string { return newTestSigner(t, "k1").sign(t, validClaims()) }, "invalid signature"},
		{"tampered_payload", func() string {
			tok := s.sign(t, validClaims())
			parts := strings.Split(tok, ".")
			c := validClaims()
			c["addresses"] = []string{"100.64.9.9/32"}
			b, _ := json.Marshal(c)
			parts[1] = base64.RawURLEncoding.EncodeToString(b)
			return strings.Join(parts, ".")
		}, "invalid signature"},
		{"alg_none", func() string {
			h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`))
			b, _ := json.Marshal(validClaims())
			return h + "." + base64.RawURLEncoding.EncodeToString(b) + "."
		}, "unsupported alg"},
		{"crit", func() string {
			h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k1","crit":["x"]}`))
			b, _ := json.Marshal(validClaims())
			in := h + "." + base64.RawURLEncoding.EncodeToString(b)
			return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.priv, []byte(in)))
		}, "critical"},
		{"malformed", func() string { return "not-a-jwt" }, "malformed"},
		{"too_many_parts", func() string { return s.sign(t, validClaims()) + ".x" }, "malformed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(tt.token(), ks, testNow)
			if err == nil {
				t.Fatalf("Verify succeeded; want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Verify error = %q; want it to contain %q", err, tt.wantErr)
			}
		})
	}

	if _, err := Verify(s.sign(t, validClaims()), nil, testNow); err == nil {
		t.Error("Verify with no keys succeeded")
	}
}

func TestKeySetFromSelfCapMap(t *testing.T) {
	s := newTestSigner(t, "good")
	ks, err := KeySetFromSelfCapMap(views.MapSliceOf(tailcfg.NodeCapMap{
		nodecap.PeerTokenKeys: {
			s.jwk(),
			`{"kty":"EC","crv":"P-256","kid":"ec","x":"AA","y":"AA"}`,
			tailcfg.RawMessage(`{"kty":"OKP","crv":"Ed25519","kid":"priv","x":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `","d":"AA"}`),
			`{"kty":"OKP","crv":"Ed25519","kid":"short","x":"AAAA"}`,
			`not json`,
		},
	}))
	if err == nil {
		t.Error("expected errors for malformed keys")
	}
	if len(ks) != 1 || ks["good"] == nil {
		t.Errorf("got keys %v; want only %q", ks, "good")
	}

	ks, err = KeySetFromSelfCapMap(views.MapSliceOf(tailcfg.NodeCapMap{}))
	if err != nil || len(ks) != 0 {
		t.Errorf("absent cap: got %v, %v", ks, err)
	}
}

func TestFilterRulesFromSelfCapMap(t *testing.T) {
	cm := tailcfg.NodeCapMap{
		"cap:b.example/x": {
			`{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":22,"Last":22}}]}`,
		},
		"cap:a.example/y": {
			`{"DstPorts":[{"IP":"100.64.0.1","Ports":{"First":80,"Last":80}}]}`,
			`garbage`,
		},
		"cap:":                  {`{}`},
		"https://unrelated/cap": {`{"SrcIPs":["*"]}`},
	}
	rules, err := FilterRulesFromSelfCapMap(views.MapSliceOf(cm))
	if err == nil {
		t.Error("expected error for malformed rule")
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules; want 2: %+v", len(rules), rules)
	}
	// Sorted by CapMap key; SrcIPs forced to the cap.
	if got := rules[0].SrcIPs; len(got) != 1 || got[0] != "cap:a.example/y" {
		t.Errorf("rules[0].SrcIPs = %q", got)
	}
	if got := rules[1].SrcIPs; len(got) != 1 || got[0] != "cap:b.example/x" {
		t.Errorf("rules[1].SrcIPs = %q (control-supplied \"*\" must be overridden)", got)
	}
	if rules[1].DstPorts[0].Ports.First != 22 {
		t.Errorf("rules[1] lost DstPorts: %+v", rules[1])
	}
}

func TestGrantedPeerCaps(t *testing.T) {
	c := &Claims{Caps: []string{
		"cap:example.com/cap/b",
		"cap:example.com/cap/a",
		"cap:example.com/cap/unknown",
		"cap:example.com/cap/a", // duplicate
		"example.com/cap/c",     // no prefix; never granted
		"cap:",                  // empty; never granted
	}}
	selfCapMap := views.MapSliceOf(tailcfg.NodeCapMap{
		"cap:example.com/cap/a": nil,
		"cap:example.com/cap/b": nil,
		"example.com/cap/c":     nil,
		"cap:":                  nil,
		"cap:example.com/cap/z": nil, // not in token
	})
	want := []nodecap.Cap{"example.com/cap/a", "example.com/cap/b"}
	if got := c.GrantedPeerCaps(selfCapMap); !slices.Equal(got, want) {
		t.Errorf("GrantedPeerCaps = %q; want %q", got, want)
	}

	if got := c.GrantedPeerCaps(views.MapSliceOf(tailcfg.NodeCapMap{"cap:example.com/cap/z": nil})); len(got) != 0 {
		t.Errorf("GrantedPeerCaps with no matching keys = %q; want none", got)
	}
}
