package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

type Forwarder struct {
	upstream    string
	domainRemap map[string]string
	udpClient   dns.Client
	tcpClient   dns.Client
}

var (
	tsHostname     = envOrDefault("TS_HOSTNAME", "tsdns")
	tsStateDir     = envOrDefault("TS_STATE_DIR", "")
	homelabZone    = envOrDefault("HOMELAB_ZONE", "homelab")
	localTLD       = envOrDefault("HOMELAB_TLD", "local")
	advertiseRoute = envOrDefault("ADVERTISE_ROUTE", "")
)

func main() {
	tsnetVerbose, err := envBoolOrDefault("TS_VERBOSE", false)
	if err != nil {
		log.Fatalf("invalid TS_VERBOSE value: %v", err)
	}
	if len(localTLD) == 0 || localTLD[0] != '.' {
		localTLD = "." + localTLD
	}

	ctx := context.Background()
	zone := strings.Trim(strings.ToLower(homelabZone), ".")
	if zone == "" {
		log.Fatalf("invalid HOMELAB_ZONE %q", homelabZone)
	}

	ts := &tsnet.Server{
		Hostname: tsHostname,
		Dir:      tsStateDir,
	}

	if tsnetVerbose {
		ts.Logf = log.New(os.Stderr, fmt.Sprintf("[tsnet:%s] ", tsHostname), log.LstdFlags).Printf
	}
	defer func() {
		_ = ts.Close()
	}()

	if _, err := ts.Up(ctx); err != nil {
		log.Fatalf("tailscale bring-up failed: %v", err)
	}

	lc, err := ts.LocalClient()
	if err != nil {
		log.Fatalf("tailscale local client failed: %v", err)
	}

	if advertiseRoute != "" {
		prefix, err := netip.ParsePrefix(advertiseRoute)
		if err != nil {
			log.Fatalf("invalid ADVERTISE_ROUTE %q: %v", advertiseRoute, err)
		}
		_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				AdvertiseRoutes: []netip.Prefix{prefix},
			},
			AdvertiseRoutesSet: true,
		})
		if err != nil {
			log.Fatalf("failed to advertise route %s: %v", prefix, err)
		}
		log.Printf("advertised route prefix to tailnet: %s", prefix)
	}

	upstream, err := defaultSystemResolver()
	if err != nil {
		log.Fatalf("failed to read system resolver: %v", err)
	}

	forwarder := &Forwarder{
		upstream: upstream,
		// Placeholder for future domain remapping rules.
		domainRemap: map[string]string{},
		udpClient:   dns.Client{Net: "udp"},
		tcpClient:   dns.Client{Net: "tcp"},
	}

	dns.HandleFunc(".", forwarder.handleRequest)
	ip4, _ := ts.TailscaleIPs()
	log.Println("My IP4:", ip4.String())
	dnsListen := ip4.String() + ":53"
	var udp net.PacketConn
	if udp, err = ts.ListenPacket("udp", dnsListen); err != nil {
		log.Fatalf("failed to listen packet conn on: %v", err)
	}
	udpServer := &dns.Server{Addr: dnsListen, Net: "udp", PacketConn: udp}
	var tcp net.Listener
	if tcp, err = ts.Listen("tcp", dnsListen); err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	tcpServer := &dns.Server{Addr: dnsListen, Net: "tcp", Listener: tcp}

	errCh := make(chan error, 2)
	go func() {
		errCh <- udpServer.ActivateAndServe()
	}()
	go func() {
		errCh <- tcpServer.ActivateAndServe()
	}()

	log.Printf("dns forwarder listening on %s (udp/tcp), upstream %s", dnsListen, upstream)

	if serveErr := <-errCh; serveErr != nil {
		log.Fatalf("dns server failed: %v", serveErr)
	}

	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()

}

func envOrDefault(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func envBoolOrDefault(key string, defaultValue bool) (bool, error) {
	value, ok := os.LookupEnv(key)
	if !ok {
		return defaultValue, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s=%q (%w)", key, value, err)
	}
	return parsed, nil
}

func defaultSystemResolver() (string, error) {
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

func (f *Forwarder) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	req := r.Copy()
	mappedResult := f.applyDomainRemap(req)

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

	f.remapDomainAnswers(resp, mappedResult)
	resp.Id = r.Id
	_ = w.WriteMsg(resp)
}

func (f *Forwarder) remapDomainAnswers(resp *dns.Msg, mapping map[string]string) {
	remapName := func(name string) string {
		if og, ok := mapping[name]; ok {
			return og
		}
		return name
	}

	// Question section — use index to actually modify the slice element
	for i := range resp.Question {
		if og, ok := mapping[resp.Question[i].Name]; ok {
			resp.Question[i].Name = og
		}
	}

	// Remap an individual RR: restore header Name + known RDATA domain fields
	remapRR := func(rr dns.RR) {
		hdr := rr.Header()
		if og, ok := mapping[hdr.Name]; ok {
			hdr.Name = og
		}
		switch v := rr.(type) {
		case *dns.CNAME:
			v.Target = remapName(v.Target)
		case *dns.DNAME:
			v.Target = remapName(v.Target)
		case *dns.NS:
			v.Ns = remapName(v.Ns)
		case *dns.MX:
			v.Mx = remapName(v.Mx)
		case *dns.SRV:
			v.Target = remapName(v.Target)
		case *dns.PTR:
			v.Ptr = remapName(v.Ptr)
		case *dns.NAPTR:
			v.Replacement = remapName(v.Replacement)
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

// return a mapping of mapped to original domain
func (f *Forwarder) applyDomainRemap(req *dns.Msg) map[string]string {
	theMap := make(map[string]string)
	for i := range req.Question {
		name := dns.Fqdn(req.Question[i].Name)
		if mapped, ok := f.domainRemap[name]; ok {
			theMap[dns.Fqdn(mapped)] = name
			req.Question[i].Name = dns.Fqdn(mapped)
			continue
		}
		if mapped, ok := remapHomelabName(name, homelabZone); ok {
			theMap[mapped] = name
			req.Question[i].Name = mapped
		}
	}
	return theMap
}

func remapHomelabName(name, homelabZone string) (string, bool) {
	indexOfTLD := strings.LastIndex(name, localTLD)
	if indexOfTLD < 0 {
		return "", false
	}
	labels := dns.SplitDomainName(name[:indexOfTLD])
	if len(labels) < 3 {
		return "", false
	}
	_len := len(labels)
	if _len < 3 {
		return "", false
	}
	labels = labels[_len-3 : _len]
	service := labels[0]
	project := labels[1]
	zone := labels[2]
	if zone != homelabZone {
		return "", false
	}
	if service == "" || project == "" {
		return "", false
	}
	mapped := fmt.Sprintf("%s-%s-1.", project, service)
	log.Println("Remapping", name, "to", mapped)
	return mapped, true
}
