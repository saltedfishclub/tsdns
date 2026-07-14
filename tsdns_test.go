package main

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParsePortRules(t *testing.T) {
	in := `
# a comment
10.1.0.3 443 10.1.0.9 8443
Caddy.Web.Homelab.Lan 80 backend.internal 8080

   # indented comment, then blank handling above
`
	rules, err := parsePortRules(strings.NewReader(in))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}

	r0 := rules[0]
	if !r0.MatchIP.IsValid() || r0.MatchIP.String() != "10.1.0.3" || r0.MatchHost != "" {
		t.Errorf("rule0 match side = %+v", r0)
	}
	if r0.MatchPort != 443 || r0.TargetHost != "10.1.0.9" || r0.TargetPort != 8443 {
		t.Errorf("rule0 = %+v", r0)
	}

	r1 := rules[1]
	if r1.MatchIP.IsValid() {
		t.Errorf("rule1 should be a domain rule, got IP %v", r1.MatchIP)
	}
	if r1.MatchHost != "caddy.web.homelab.lan." { // lower-cased + fully qualified
		t.Errorf("rule1 MatchHost = %q, want caddy.web.homelab.lan.", r1.MatchHost)
	}
}

func TestParsePortRulesErrors(t *testing.T) {
	cases := []string{
		"10.1.0.3 443 10.1.0.9",            // too few fields
		"10.1.0.3 443 10.1.0.9 8443 extra", // too many fields
		"10.1.0.3 notaport 10.1.0.9 8443",  // bad original port
		"10.1.0.3 0 10.1.0.9 8443",         // zero port
		"10.1.0.3 443 10.1.0.9 70000",      // port out of range
	}
	for _, c := range cases {
		if _, err := parsePortRules(strings.NewReader(c)); err == nil {
			t.Errorf("expected error for %q, got nil", c)
		}
	}
}

func TestPortRulesMatch(t *testing.T) {
	rules := PortRules{
		{MatchIP: netip.MustParseAddr("10.1.0.3"), MatchPort: 443, TargetHost: "10.1.0.9", TargetPort: 8443},
		{MatchHost: "caddy.web.homelab.lan.", MatchPort: 80, TargetHost: "backend", TargetPort: 8080},
	}
	lookup := func(name string) []netip.Addr {
		if name == "caddy.web.homelab.lan." {
			return []netip.Addr{netip.MustParseAddr("10.1.0.5")}
		}
		return nil
	}

	if r, ok := rules.Match(netip.MustParseAddrPort("10.1.0.3:443"), lookup); !ok || r.TargetPort != 8443 {
		t.Errorf("IP match failed: %+v ok=%v", r, ok)
	}
	if _, ok := rules.Match(netip.MustParseAddrPort("10.1.0.3:444"), lookup); ok {
		t.Errorf("must not match on wrong port")
	}
	if r, ok := rules.Match(netip.MustParseAddrPort("10.1.0.5:80"), lookup); !ok || r.TargetHost != "backend" {
		t.Errorf("domain match failed: %+v ok=%v", r, ok)
	}
	if _, ok := rules.Match(netip.MustParseAddrPort("10.1.0.6:80"), lookup); ok {
		t.Errorf("must not match an IP absent from the cache")
	}
}

func TestResolveCachePutLookup(t *testing.T) {
	c := NewResolveCache()
	now := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return now }

	want := netip.MustParseAddr("10.1.0.3")
	c.Put("Caddy.Web.Homelab.Lan", []netip.Addr{want}, time.Minute)

	// Lookups are case-insensitive and trailing-dot-insensitive.
	for _, name := range []string{"caddy.web.homelab.lan.", "caddy.web.homelab.lan", "CADDY.web.homelab.LAN"} {
		got := c.Lookup(name)
		if len(got) != 1 || got[0] != want {
			t.Fatalf("Lookup(%q) = %v, want [%v]", name, got, want)
		}
	}

	now = now.Add(2 * time.Minute) // past the 1m TTL
	if got := c.Lookup("caddy.web.homelab.lan."); got != nil {
		t.Fatalf("expected expired entry, got %v", got)
	}
}

func TestResolveCacheMinTTL(t *testing.T) {
	c := NewResolveCache()
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }

	c.Put("x.", []netip.Addr{netip.MustParseAddr("1.2.3.4")}, time.Second) // clamped up to minCacheTTL

	now = now.Add(minCacheTTL / 2)
	if got := c.Lookup("x."); len(got) != 1 {
		t.Fatalf("entry should survive the min-TTL clamp, got %v", got)
	}
}

func TestResolveCacheIgnoresEmpty(t *testing.T) {
	c := NewResolveCache()
	c.Put("y.", nil, time.Minute)
	if got := c.Lookup("y."); got != nil {
		t.Fatalf("empty Put should be ignored, got %v", got)
	}
}

func TestAddrFromIP(t *testing.T) {
	if a, ok := addrFromIP(net.ParseIP("10.0.0.1")); !ok || a.String() != "10.0.0.1" {
		t.Errorf("addrFromIP(v4) = %v, %v", a, ok)
	}
	if a, ok := addrFromIP(net.ParseIP("::ffff:10.0.0.1")); !ok || a.String() != "10.0.0.1" {
		t.Errorf("addrFromIP(v4-in-v6) should unmap, got %v, %v", a, ok)
	}
}

func testForwarder() *Forwarder {
	cfg := &Config{HomelabZone: "homelab", LocalTLD: ".lan"}
	return NewForwarder(cfg, "127.0.0.1:53", net.ParseIP("100.64.0.1"), NewResolveCache())
}

func TestRemapHomelabName(t *testing.T) {
	f := testForwarder()
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"caddy.web.homelab.lan.", "web-caddy-1.", true},
		{"a.b.homelab.lan.", "b-a-1.", true},
		{"web.homelab.lan.", "", false},     // too few labels
		{"caddy.web.other.lan.", "", false}, // wrong zone
		{"example.com.", "", false},         // not the local TLD
	}
	for _, c := range cases {
		if got, ok := f.remapHomelabName(c.in); ok != c.wantOK || got != c.want {
			t.Errorf("remapHomelabName(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

func TestCacheAnswers(t *testing.T) {
	f := testForwarder()
	resp := new(dns.Msg)
	resp.Question = []dns.Question{{Name: "caddy.web.homelab.lan.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "caddy.web.homelab.lan.", Rrtype: dns.TypeA, Ttl: 120},
			A:   net.ParseIP("10.1.0.3"),
		},
	}
	f.cacheAnswers(resp)

	got := f.cache.Lookup("caddy.web.homelab.lan.")
	if len(got) != 1 || got[0] != netip.MustParseAddr("10.1.0.3") {
		t.Fatalf("cacheAnswers populated %v, want [10.1.0.3]", got)
	}
}
