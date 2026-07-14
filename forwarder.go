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
	selfIP      net.IP

	// domainRemap is an optional static name→name rewrite applied before the
	// homelab convention. Currently unused but kept as an extension point.
	domainRemap map[string]string

	cache *ResolveCache

	udpClient dns.Client
	tcpClient dns.Client
}

// NewForwarder builds a Forwarder from the config, its resolved upstream, this
// node's Tailscale IP, and the shared resolution cache.
func NewForwarder(cfg *Config, upstream string, selfIP net.IP, cache *ResolveCache) *Forwarder {
	return &Forwarder{
		upstream:    upstream,
		homelabZone: cfg.HomelabZone,
		localTLD:    cfg.LocalTLD,
		selfZone:    dns.Fqdn(cfg.SelfZone()),
		selfIP:      selfIP,
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

// answerSelfZone replies to an A query for the homelab zone itself with this
// node's Tailscale IP. Returns true if it handled the request.
func (f *Forwarder) answerSelfZone(w dns.ResponseWriter, r *dns.Msg) bool {
	if f.selfIP == nil || len(r.Question) != 1 {
		return false
	}
	q := r.Question[0]
	if q.Qclass != dns.ClassINET || q.Qtype != dns.TypeA || !strings.EqualFold(dns.Fqdn(q.Name), f.selfZone) {
		return false
	}

	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   f.selfIP,
	})
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
	mapped := fmt.Sprintf("%s-%s-1.", project, service)
	log.Println("Remapping", name, "to", mapped)
	return mapped, true
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
