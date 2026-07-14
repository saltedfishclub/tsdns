package main

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// PortRule redirects connections destined for one (address, port) to another.
//
// The matched ("original") destination is either a literal IP (MatchIP is set)
// or a domain (MatchHost is set), in which case the domain is resolved through
// the shared ResolveCache at match time. The rewritten ("target") destination
// is dialed by the subnet router.
type PortRule struct {
	MatchIP   netip.Addr // set when the original destination was a literal IP
	MatchHost string     // set (lower-cased) when it was a domain
	MatchPort uint16

	TargetHost string // literal IP or domain, as written
	TargetPort uint16
}

// Source renders the matched side of the rule for logging.
func (r PortRule) Source() string {
	host := r.MatchHost
	if r.MatchIP.IsValid() {
		host = r.MatchIP.String()
	}
	return fmt.Sprintf("%s:%d", host, r.MatchPort)
}

// PortRules is an ordered list of rules; the first match wins.
type PortRules []PortRule

// Match returns the first rule whose original destination matches dst. Domain
// rules are resolved via lookup, which should return the cached IPs for a name.
func (rs PortRules) Match(dst netip.AddrPort, lookup func(name string) []netip.Addr) (PortRule, bool) {
	addr := dst.Addr().Unmap()
	for _, r := range rs {
		if r.MatchPort != dst.Port() {
			continue
		}
		if r.MatchIP.IsValid() {
			if r.MatchIP == addr {
				return r, true
			}
			continue
		}
		for _, ip := range lookup(r.MatchHost) {
			if ip.Unmap() == addr {
				return r, true
			}
		}
	}
	return PortRule{}, false
}

// LoadPortRules parses a port-mapping file. Each non-empty, non-comment line is
//
//	<original-dest> <original-port> <rewritten-dest> <rewritten-port>
//
// where a destination is a literal IP or a domain name. Lines beginning with
// '#' and blank lines are ignored.
func LoadPortRules(path string) (PortRules, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parsePortRules(f)
}

func parsePortRules(r io.Reader) (PortRules, error) {
	var rules PortRules
	sc := bufio.NewScanner(r)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := parsePortRule(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		rules = append(rules, rule)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func parsePortRule(line string) (PortRule, error) {
	fields := strings.Fields(line)
	if len(fields) != 4 {
		return PortRule{}, fmt.Errorf("expected 4 fields <orig-dest> <orig-port> <new-dest> <new-port>, got %d", len(fields))
	}

	matchPort, err := parsePort(fields[1])
	if err != nil {
		return PortRule{}, fmt.Errorf("original port %q: %w", fields[1], err)
	}
	targetPort, err := parsePort(fields[3])
	if err != nil {
		return PortRule{}, fmt.Errorf("rewritten port %q: %w", fields[3], err)
	}

	rule := PortRule{
		MatchPort:  matchPort,
		TargetHost: fields[2],
		TargetPort: targetPort,
	}
	if ip, err := netip.ParseAddr(fields[0]); err == nil {
		rule.MatchIP = ip.Unmap()
	} else {
		rule.MatchHost = canonicalName(fields[0])
	}
	return rule, nil
}

func parsePort(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("not a valid port: %w", err)
	}
	if p == 0 {
		return 0, fmt.Errorf("port must be non-zero")
	}
	return uint16(p), nil
}
