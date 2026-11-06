// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package peertoken verifies control-signed peer tokens.
//
// A peer token is a JWT (RFC 7519), signed by the control plane, that
// authorizes the node it describes to communicate with any node that trusts
// the signing key, even if those nodes don't have it in their netmap. A node
// presents its peer token to another node in a [disco.PeerToken] message.
//
// Tokens are compact-serialized JWS objects signed with EdDSA (Ed25519).
// The signing keys are distributed to the receiving node as JSON Web Keys in
// its self node's CapMap under [nodecap.PeerTokenKeys].
//
// The token binds the sender's node key and disco key. A recipient must check
// that the disco message carrying the token was sealed by [Claims.DiscoKey];
// the WireGuard handshake then proves possession of [Claims.NodeKey]. A stolen
// token is thus useless without the corresponding private keys.
//
// The token lists, in [Claims.Caps], the node capabilities it may grant the
// peer, each of the form "cap:<peer-node-capability>". A recipient only
// accepts the token if its own self node's CapMap contains at least one of
// those same "cap:..." keys, and grants the peer only the capabilities whose
// keys it contains (see [Claims.GrantedPeerCaps]). The values under each such
// key are the [tailcfg.FilterRule]s governing what peers with that
// capability may access. See [FilterRulesFromSelfCapMap].
//
// [disco.PeerToken]: https://pkg.go.dev/tailscale.com/disco#PeerToken
package peertoken

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/disco"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// CapPrefix is the prefix of each of [Claims.Caps] and of the corresponding
// self node CapMap key holding the packet filter rules for peers with that
// capability.
const CapPrefix = "cap:"

// NotBeforeLeeway is how far in the future a token's "nbf" or "iat" may be,
// to tolerate clock skew between control and this node. There is no leeway
// on "exp": a token is never honored past its expiry.
const NotBeforeLeeway = time.Minute

// Claims are the verified contents of a peer token.
type Claims struct {
	// Issuer is the "iss" claim. It's informational only.
	Issuer string `json:"iss,omitempty"`

	// Subject is the "sub" claim, if present. If non-empty, it's used as the
	// peer's [tailcfg.StableNodeID].
	Subject string `json:"sub,omitempty"`

	// Expiry is the "exp" claim. It's required.
	Expiry time.Time `json:"-"`

	// NotBefore is the "nbf" claim, or the zero time if absent.
	NotBefore time.Time `json:"-"`

	// IssuedAt is the "iat" claim, or the zero time if absent.
	IssuedAt time.Time `json:"-"`

	// NodeID is the peer's node ID as assigned by control. Required.
	NodeID tailcfg.NodeID `json:"node_id"`

	// NodeKey is the peer's WireGuard public key. Required.
	NodeKey key.NodePublic `json:"node_key"`

	// DiscoKey is the peer's disco public key. Required.
	DiscoKey key.DiscoPublic `json:"disco_key"`

	// Addresses are the peer's tailnet IP addresses, each a single-IP prefix
	// within the Tailscale address ranges. At least one is required. The
	// peer is allowed to originate traffic from exactly these addresses.
	Addresses []netip.Prefix `json:"addresses"`

	// Caps are the node capabilities the token may grant the peer, each of
	// the form "cap:<peer-node-capability>". At least one is required.
	//
	// A recipient grants the peer only those of Caps whose "cap:..." key is
	// in its own self node's CapMap; see [Claims.GrantedPeerCaps].
	Caps []string `json:"caps"`
}

// GrantedPeerCaps returns the peer node capabilities that a recipient whose
// self node has the given CapMap grants to the peer: those of c.Caps whose
// "cap:..." key is in selfCapMap, without the "cap:" prefix. Those are the
// capabilities the peer's synthesized node carries, and that "cap:..." filter
// rule sources match.
//
// The result is sorted and has no duplicates. It's empty if the recipient
// grants none of c.Caps, in which case it must reject the token.
func (c *Claims) GrantedPeerCaps(selfCapMap views.MapSlice[nodecap.Cap, tailcfg.RawMessage]) []nodecap.Cap {
	var caps []nodecap.Cap
	for _, k := range c.Caps {
		peerCap, ok := strings.CutPrefix(k, CapPrefix)
		if !ok || peerCap == "" || !selfCapMap.Contains(nodecap.Cap(k)) {
			continue
		}
		caps = append(caps, nodecap.Cap(peerCap))
	}
	slices.Sort(caps)
	return slices.Compact(caps)
}

// KeySet is a set of trusted peer token signing keys, indexed by key ID.
type KeySet map[string]ed25519.PublicKey

// jwk is the subset of a JSON Web Key that we support.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	D   string `json:"d"` // must be absent; a private key here is a control bug
}

// KeySetFromSelfCapMap parses the [nodecap.PeerTokenKeys] values of the self
// node's CapMap. It returns an empty set (and no error) if the capability is
// absent. Malformed keys are skipped and reported in the returned error, but
// the valid keys are still returned.
func KeySetFromSelfCapMap(capMap views.MapSlice[nodecap.Cap, tailcfg.RawMessage]) (KeySet, error) {
	vals, ok := capMap.GetOk(nodecap.PeerTokenKeys)
	if !ok {
		return nil, nil
	}
	ks := make(KeySet)
	var errs []error
	for _, v := range vals.All() {
		var k jwk
		if err := json.Unmarshal([]byte(v), &k); err != nil {
			errs = append(errs, fmt.Errorf("parsing JWK: %w", err))
			continue
		}
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			errs = append(errs, fmt.Errorf("JWK %q: unsupported kty %q / crv %q", k.Kid, k.Kty, k.Crv))
			continue
		}
		if k.D != "" {
			errs = append(errs, fmt.Errorf("JWK %q: contains private key material", k.Kid))
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			errs = append(errs, fmt.Errorf("JWK %q: unsupported use %q", k.Kid, k.Use))
			continue
		}
		if k.Alg != "" && k.Alg != "EdDSA" {
			errs = append(errs, fmt.Errorf("JWK %q: unsupported alg %q", k.Kid, k.Alg))
			continue
		}
		pub, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			errs = append(errs, fmt.Errorf("JWK %q: invalid x", k.Kid))
			continue
		}
		if _, dup := ks[k.Kid]; dup {
			errs = append(errs, fmt.Errorf("JWK %q: duplicate key ID", k.Kid))
			continue
		}
		ks[k.Kid] = ed25519.PublicKey(pub)
	}
	return ks, errors.Join(errs...)
}

type header struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Crit []string `json:"crit"`
}

// wireClaims is the JSON form of [Claims], with NumericDate fields.
type wireClaims struct {
	Claims
	Exp *json.Number `json:"exp"`
	Nbf *json.Number `json:"nbf"`
	Iat *json.Number `json:"iat"`
}

// Verify verifies token against the trusted keys in ks as of now, and
// returns its claims.
//
// Verify checks the signature, the time-based claims, and that the required
// claims are present and well-formed. It does not check the token against the
// disco message that carried it, nor against the current netmap; callers must
// do that.
func Verify(token string, ks KeySet, now time.Time) (*Claims, error) {
	if len(ks) == 0 {
		return nil, errors.New("no trusted peer token keys")
	}
	if len(token) > disco.MaxPeerTokenLen {
		return nil, errors.New("token too long")
	}
	hdrB64, rest, ok := strings.Cut(token, ".")
	if !ok {
		return nil, errors.New("malformed token")
	}
	payloadB64, sigB64, ok := strings.Cut(rest, ".")
	if !ok || strings.Contains(sigB64, ".") {
		return nil, errors.New("malformed token")
	}

	hdrJSON, err := base64.RawURLEncoding.DecodeString(hdrB64)
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}
	var hdr header
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, fmt.Errorf("parsing header: %w", err)
	}
	if hdr.Alg != "EdDSA" {
		return nil, fmt.Errorf("unsupported alg %q", hdr.Alg)
	}
	if len(hdr.Crit) > 0 {
		return nil, fmt.Errorf("unsupported critical header parameters %q", hdr.Crit)
	}
	if hdr.Typ != "" && !strings.EqualFold(hdr.Typ, "JWT") {
		return nil, fmt.Errorf("unsupported typ %q", hdr.Typ)
	}
	pub, ok := ks[hdr.Kid]
	if !ok {
		return nil, fmt.Errorf("unknown signing key ID %q", hdr.Kid)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}
	signingInput := token[:len(hdrB64)+1+len(payloadB64)]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, errors.New("invalid signature")
	}

	// The signature is valid; the payload came from control.
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	var wc wireClaims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&wc); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}
	c := &wc.Claims
	if c.Expiry, err = numericDate(wc.Exp); err != nil {
		return nil, fmt.Errorf("exp: %w", err)
	}
	if c.NotBefore, err = numericDate(wc.Nbf); err != nil {
		return nil, fmt.Errorf("nbf: %w", err)
	}
	if c.IssuedAt, err = numericDate(wc.Iat); err != nil {
		return nil, fmt.Errorf("iat: %w", err)
	}
	if err := c.validate(now); err != nil {
		return nil, err
	}
	return c, nil
}

func numericDate(n *json.Number) (time.Time, error) {
	if n == nil {
		return time.Time{}, nil
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 || f > 1<<40 {
		return time.Time{}, fmt.Errorf("invalid NumericDate %q", n.String())
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), nil
}

func (c *Claims) validate(now time.Time) error {
	if c.Expiry.IsZero() {
		return errors.New("missing exp")
	}
	if !now.Before(c.Expiry) {
		return fmt.Errorf("token expired at %v", c.Expiry.UTC().Format(time.RFC3339))
	}
	if !c.NotBefore.IsZero() && now.Add(NotBeforeLeeway).Before(c.NotBefore) {
		return fmt.Errorf("token not valid until %v", c.NotBefore.UTC().Format(time.RFC3339))
	}
	if !c.IssuedAt.IsZero() && now.Add(NotBeforeLeeway).Before(c.IssuedAt) {
		return fmt.Errorf("token issued in the future (%v)", c.IssuedAt.UTC().Format(time.RFC3339))
	}
	if c.NodeID <= 0 {
		return errors.New("missing or invalid node_id")
	}
	if c.NodeKey.IsZero() {
		return errors.New("missing node_key")
	}
	if c.DiscoKey.IsZero() {
		return errors.New("missing disco_key")
	}
	if len(c.Addresses) == 0 {
		return errors.New("missing addresses")
	}
	for _, p := range c.Addresses {
		if !p.IsValid() || !p.IsSingleIP() || !tsaddr.IsTailscaleIP(p.Addr()) {
			return fmt.Errorf("invalid address %v: must be a single Tailscale IP", p)
		}
	}
	if len(c.Caps) == 0 {
		return errors.New("missing caps")
	}
	for _, k := range c.Caps {
		if peerCap, ok := strings.CutPrefix(k, CapPrefix); !ok || peerCap == "" {
			return fmt.Errorf("invalid cap %q: must be of the form %q", k, CapPrefix+"<peer-node-capability>")
		}
	}
	return nil
}

// FilterRulesFromSelfCapMap returns the packet filter rules granted to peers
// holding peer-token capabilities, from the self node's CapMap.
//
// Each self CapMap key of the form "cap:<peer-node-capability>" has values
// that are JSON-encoded [tailcfg.FilterRule]s. Their SrcIPs are replaced with
// the single source "cap:<peer-node-capability>", so that each rule only
// ever applies to peers holding that capability, regardless of what SrcIPs
// control sent. Malformed rules are skipped and reported in the returned
// error.
func FilterRulesFromSelfCapMap(capMap views.MapSlice[nodecap.Cap, tailcfg.RawMessage]) ([]tailcfg.FilterRule, error) {
	var keys []nodecap.Cap
	for k := range capMap.All() {
		if peerCap, ok := strings.CutPrefix(string(k), CapPrefix); ok && peerCap != "" {
			keys = append(keys, k)
		}
	}
	// Sort for a deterministic rule order, so that callers' change
	// detection on the resulting filter is stable.
	slices.Sort(keys)

	var rules []tailcfg.FilterRule
	var errs []error
	for _, k := range keys {
		for _, v := range capMap.Get(k).All() {
			var r tailcfg.FilterRule
			if err := json.Unmarshal([]byte(v), &r); err != nil {
				errs = append(errs, fmt.Errorf("%s: parsing filter rule: %w", k, err))
				continue
			}
			r.SrcIPs = []string{string(k)}
			r.SrcBits = nil
			rules = append(rules, r)
		}
	}
	return rules, errors.Join(errs...)
}
