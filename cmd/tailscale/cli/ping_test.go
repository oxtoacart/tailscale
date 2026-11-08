// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
)

// TestMagicDNSIPFromArg checks that names in the tailnet's MagicDNS domain
// are resolved with tailscaled's MagicDNS (over the LocalAPI), and others
// aren't.
func TestMagicDNSIPFromArg(t *testing.T) {
	records := map[string][4]byte{"c2.foo.ts.net.": {100, 64, 0, 2}}
	var (
		mu      sync.Mutex
		queries []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/localapi/v0/dns-query" {
			http.NotFound(w, r)
			return
		}
		name, typ := r.URL.Query().Get("name"), r.URL.Query().Get("type")
		mu.Lock()
		queries = append(queries, name+"/"+typ)
		mu.Unlock()
		fqdn := strings.TrimSuffix(name, ".") + "."
		qtype := dnsmessage.TypeA
		if typ == "AAAA" {
			qtype = dnsmessage.TypeAAAA
		}
		a, ok := records[fqdn]
		h := dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess}
		if !ok {
			h.RCode = dnsmessage.RCodeNameError
		}
		b := dnsmessage.NewBuilder(nil, h)
		b.StartQuestions()
		n := dnsmessage.MustNewName(fqdn)
		b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: dnsmessage.ClassINET})
		b.StartAnswers()
		if ok && qtype == dnsmessage.TypeA {
			b.AResource(dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 5}, dnsmessage.AResource{A: a})
		}
		msg, err := b.Finish()
		if err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(apitype.DNSQueryResponse{Bytes: msg})
	}))
	defer srv.Close()

	oldDial := localClient.Dial
	localClient.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}
	defer func() { localClient.Dial = oldDial }()

	st := &ipnstate.Status{CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "foo.ts.net"}}
	for _, tt := range []struct {
		host   string
		want   string
		wantQs []string // queries sent; nil means none
	}{
		{"c2.foo.ts.net", "100.64.0.2", []string{"c2.foo.ts.net/A"}},
		{"c2.foo.ts.net.", "100.64.0.2", []string{"c2.foo.ts.net/A"}},
		{"C2.Foo.TS.net", "100.64.0.2", []string{"c2.foo.ts.net/A"}},
		{"c2", "100.64.0.2", []string{"c2.foo.ts.net/A"}},
		{"nope.foo.ts.net", "", []string{"nope.foo.ts.net/A", "nope.foo.ts.net/AAAA"}},
		{"example.com", "", nil},
		{"c2.bar.ts.net", "", nil},
	} {
		mu.Lock()
		queries = nil
		mu.Unlock()
		got, ok := magicDNSIPFromArg(t.Context(), st, tt.host)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("magicDNSIPFromArg(%q) = %q, %v; want %q", tt.host, got, ok, tt.want)
		}
		mu.Lock()
		if !slices.Equal(queries, tt.wantQs) {
			t.Errorf("magicDNSIPFromArg(%q) queries = %q; want %q", tt.host, queries, tt.wantQs)
		}
		mu.Unlock()
	}

	// Without a MagicDNS suffix, nothing is queried.
	if _, ok := magicDNSIPFromArg(t.Context(), &ipnstate.Status{}, "c2"); ok {
		t.Error("resolved without a MagicDNS suffix")
	}
}
