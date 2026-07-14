package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Forwarder is a recursive DNS server that answers for the local homelab zone,
// rewrites homelab names onto their backing container names before forwarding
// to the upstream resolver, and remembers every answer in a ResolveCache.
type Forwarder struct {
	upstream string

	homelabZone string // e.g. "homelab"
	localTLD    string // e.g. ".lan"
	selfZone    string // FQDN answered with this node's own IP, e.g. "homelab.lan."
	self4       netip.Addr
	self6       netip.Addr

	// domainRemap is an optional static name→name rewrite applied before the
	// homelab convention. Currently unused but kept as an extension point.
	domainRemap map[string]string

	cache *ResolveCache

	udpClient dns.Client
	tcpClient dns.Client
}

// NewForwarder builds a Forwarder from the config, its resolved upstream, this
// node's Tailscale IPs, and the shared resolution cache.
func NewForwarder(cfg *Config, upstream string, self4, self6 netip.Addr, cache *ResolveCache) *Forwarder {
	return &Forwarder{
		upstream:    upstream,
		homelabZone: cfg.HomelabZone,
		localTLD:    cfg.LocalTLD,
		selfZone:    dns.Fqdn(cfg.SelfZone()),
		self4:       self4,
		self6:       self6,
		domainRemap: map[string]string{},
		cache:       cache,
		udpClient:   dns.Client{Net: "udp"},
		tcpClient:   dns.Client{Net: "tcp"},
	}
}

// HandleRequest is the dns.Handler entry point.
func (f *Forwarder) HandleRequest(w dns.ResponseWriter, r *dns.Msg) {
	logQuery(w, r)

	if f.answerSelfZone(w, r) {
		return
	}

	req := r.Copy()
	restore := f.applyDomainRemap(req)

	resp, _, err := f.udpClient.Exchange(req, f.upstream)
	if err == nil && resp != nil && resp.Truncated {
		resp, _, err = f.tcpClient.Exchange(req, f.upstream)
	}
	if err != nil || resp == nil {
		fail := new(dns.Msg)
		fail.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(fail)
		return
	}

	f.remapDomainAnswers(resp, restore)
	resp.Id = r.Id
	f.cacheAnswers(resp)
	_ = w.WriteMsg(resp)
}

// answerSelfZone authoritatively answers A/AAAA queries for the homelab zone
// itself with this node's Tailscale IPs. It returns true if it handled the
// request, including the NODATA case (an authoritative empty reply) so such
// queries never leak to the upstream. Returns false only when the node has no
// address at all.
func (f *Forwarder) answerSelfZone(w dns.ResponseWriter, r *dns.Msg) bool {
	if !f.self4.IsValid() && !f.self6.IsValid() {
		return false
	}
	if len(r.Question) != 1 {
		return false
	}
	q := r.Question[0]
	if q.Qclass != dns.ClassINET || !strings.EqualFold(dns.Fqdn(q.Name), f.selfZone) {
		return false
	}
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return false
	}

	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true
	if q.Qtype == dns.TypeA && f.self4.IsValid() {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   f.self4.AsSlice(),
		})
	}
	if q.Qtype == dns.TypeAAAA && f.self6.IsValid() {
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: f.self6.AsSlice(),
		})
	}
	_ = w.WriteMsg(resp)
	return true
}

// applyDomainRemap rewrites the request's question names in place, first via
// the static domainRemap table and then via the homelab convention. It returns
// a map from each rewritten name back to the original so the answer can be
// restored to what the client asked for.
func (f *Forwarder) applyDomainRemap(req *dns.Msg) map[string]string {
	restore := make(map[string]string)
	for i := range req.Question {
		name := dns.Fqdn(req.Question[i].Name)
		if mapped, ok := f.domainRemap[name]; ok {
			mapped = dns.Fqdn(mapped)
			restore[mapped] = name
			req.Question[i].Name = mapped
			continue
		}
		if mapped, ok := f.remapHomelabName(name); ok {
			log.Println("Remapping", name, "to", mapped)
			restore[mapped] = name
			req.Question[i].Name = mapped
		}
	}
	return restore
}

// remapHomelabName maps "<service>.<project>.<zone><tld>" to the container name
// "<project>-<service>-1." that the upstream (Docker's embedded DNS) resolves.
func (f *Forwarder) remapHomelabName(name string) (string, bool) {
	i := strings.LastIndex(name, f.localTLD)
	if i < 0 {
		return "", false
	}
	labels := dns.SplitDomainName(name[:i])
	if len(labels) < 3 {
		return "", false
	}
	labels = labels[len(labels)-3:]
	service, project, zone := labels[0], labels[1], labels[2]
	if zone != f.homelabZone || service == "" || project == "" {
		return "", false
	}
	return fmt.Sprintf("%s-%s-1.", project, service), true
}

// remapQuery returns the name that should actually be queried upstream for the
// given client-facing name, applying the static and homelab remaps.
func (f *Forwarder) remapQuery(fqdn string) string {
	if mapped, ok := f.domainRemap[fqdn]; ok {
		return dns.Fqdn(mapped)
	}
	if mapped, ok := f.remapHomelabName(fqdn); ok {
		return mapped
	}
	return fqdn
}

// remapDomainAnswers restores rewritten names in a response back to the names
// the client originally asked for, covering the question, header, and the
// domain-valued RDATA of common record types.
func (f *Forwarder) remapDomainAnswers(resp *dns.Msg, restore map[string]string) {
	if len(restore) == 0 {
		return
	}
	orig := func(name string) string {
		if og, ok := restore[name]; ok {
			return og
		}
		return name
	}

	for i := range resp.Question {
		resp.Question[i].Name = orig(resp.Question[i].Name)
	}

	remapRR := func(rr dns.RR) {
		hdr := rr.Header()
		hdr.Name = orig(hdr.Name)
		switch v := rr.(type) {
		case *dns.CNAME:
			v.Target = orig(v.Target)
		case *dns.DNAME:
			v.Target = orig(v.Target)
		case *dns.NS:
			v.Ns = orig(v.Ns)
		case *dns.MX:
			v.Mx = orig(v.Mx)
		case *dns.SRV:
			v.Target = orig(v.Target)
		case *dns.PTR:
			v.Ptr = orig(v.Ptr)
		case *dns.NAPTR:
			v.Replacement = orig(v.Replacement)
		}
	}
	for _, rr := range resp.Answer {
		remapRR(rr)
	}
	for _, rr := range resp.Ns {
		remapRR(rr)
	}
	for _, rr := range resp.Extra {
		remapRR(rr)
	}
}

// cacheAnswers records the A/AAAA addresses of a response under each A/AAAA
// question name, so the subnet router can later map a hijack rule's domain to
// the addresses a connection might target.
func (f *Forwarder) cacheAnswers(resp *dns.Msg) {
	if f.cache == nil || len(resp.Answer) == 0 {
		return
	}

	var ips []netip.Addr
	var ttl uint32
	for _, rr := range resp.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		default:
			continue
		}
		if a, ok := addrFromIP(ip); ok {
			ips = append(ips, a)
			if h := rr.Header().Ttl; ttl == 0 || h < ttl {
				ttl = h
			}
		}
	}
	if len(ips) == 0 {
		return
	}

	for _, q := range resp.Question {
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			f.cache.Put(q.Name, ips, time.Duration(ttl)*time.Second)
		}
	}
}

func logQuery(w dns.ResponseWriter, r *dns.Msg) {
	questions := make([]string, 0, len(r.Question))
	for _, q := range r.Question {
		questions = append(questions, fmt.Sprintf("%s %s", q.Name, dns.TypeToString[q.Qtype]))
	}
	log.Printf("query from %s (%s): %s",
		w.RemoteAddr().String(), w.RemoteAddr().Network(), strings.Join(questions, ", "))
}

// selfZoneTTL is the cache lifetime used for the node's own zone, which never
// changes; the background resolver re-affirms it well within this window.
const selfZoneTTL = 5 * time.Minute

// Resolve looks up the addresses of name using the same pipeline as
// HandleRequest: the self zone is answered locally, other names are
// homelab-remapped and queried upstream (A records). It returns the addresses
// and the smallest record TTL, and is used to keep hijack rules resolvable
// without depending on client query traffic.
func (f *Forwarder) Resolve(name string) ([]netip.Addr, time.Duration, error) {
	fqdn := dns.Fqdn(name)

	if strings.EqualFold(fqdn, f.selfZone) {
		var ips []netip.Addr
		if f.self4.IsValid() {
			ips = append(ips, f.self4)
		}
		if f.self6.IsValid() {
			ips = append(ips, f.self6)
		}
		return ips, selfZoneTTL, nil
	}

	m := new(dns.Msg)
	m.SetQuestion(f.remapQuery(fqdn), dns.TypeA)
	resp, _, err := f.udpClient.Exchange(m, f.upstream)
	if err != nil {
		return nil, 0, err
	}
	if resp == nil {
		return nil, 0, fmt.Errorf("no response from upstream")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("upstream rcode %s", dns.RcodeToString[resp.Rcode])
	}

	var ips []netip.Addr
	var ttl uint32
	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		if ip, ok := addrFromIP(a.A); ok {
			ips = append(ips, ip)
			if ttl == 0 || a.Hdr.Ttl < ttl {
				ttl = a.Hdr.Ttl
			}
		}
	}
	return ips, time.Duration(ttl) * time.Second, nil
}

const ruleRefreshInterval = 30 * time.Second

// StartRuleResolver keeps the resolution cache warm for every domain used as a
// port rule's original destination, so hijack matching works even when a client
// resolves the name from its own DNS cache (or after tsdns restarts while the
// client's cache is still valid). It resolves once synchronously, then refreshes
// in the background.
func StartRuleResolver(f *Forwarder, cache *ResolveCache, rules PortRules) {
	seen := make(map[string]bool)
	var domains []string
	for _, r := range rules {
		if r.MatchHost != "" && !seen[r.MatchHost] {
			seen[r.MatchHost] = true
			domains = append(domains, r.MatchHost)
		}
	}
	if len(domains) == 0 {
		return
	}

	refresh := func() {
		for _, d := range domains {
			ips, ttl, err := f.Resolve(d)
			if err != nil {
				log.Printf("port-map: cannot resolve rule domain %s: %v", d, err)
				continue
			}
			if len(ips) == 0 {
				log.Printf("port-map: rule domain %s resolved to no addresses", d)
				continue
			}
			cache.Put(d, ips, ttl)
		}
	}

	refresh() // warm the cache before serving/routing begins
	go func() {
		for {
			time.Sleep(ruleRefreshInterval)
			refresh()
		}
	}()
}

// SystemUpstream reads the first nameserver from /etc/resolv.conf and returns
// it as a host:port string.
func SystemUpstream() (string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	if len(cfg.Servers) == 0 {
		return "", fmt.Errorf("no system DNS servers in /etc/resolv.conf")
	}
	port := cfg.Port
	if port == "" {
		port = "53"
	}
	return net.JoinHostPort(cfg.Servers[0], port), nil
}
