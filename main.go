package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"

	"github.com/miekg/dns"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()

	ts := &tsnet.Server{
		Hostname: cfg.Hostname,
		Dir:      cfg.StateDir,
		Port:     cfg.PreferPort,
	}
	if cfg.Verbose {
		ts.Logf = log.New(os.Stderr, fmt.Sprintf("[tsnet:%s] ", cfg.Hostname), log.LstdFlags).Printf
	}
	defer ts.Close()

	if _, err := ts.Up(ctx); err != nil {
		log.Fatalf("tailscale bring-up failed: %v", err)
	}

	ip4, _ := ts.TailscaleIPs()
	log.Println("My IP4:", ip4.String())

	cache := NewResolveCache()

	if err := setupSubnetRouting(ctx, ts, cfg, cache); err != nil {
		log.Fatalf("subnet routing: %v", err)
	}

	upstream, err := SystemUpstream()
	if err != nil {
		log.Fatalf("failed to read system resolver: %v", err)
	}

	forwarder := NewForwarder(cfg, upstream, net.IP(ip4.AsSlice()), cache)
	if err := serveDNS(ts, forwarder, ip4.String()+":53", upstream); err != nil {
		log.Fatalf("dns server failed: %v", err)
	}
}

// setupSubnetRouting advertises the configured route and, when running in
// userspace forwarding mode, installs the subnet router (which also applies
// port-mapping hijack rules).
func setupSubnetRouting(ctx context.Context, ts *tsnet.Server, cfg *Config, cache *ResolveCache) error {
	rules, err := loadPortRules(cfg)
	if err != nil {
		return err
	}

	if !cfg.AdvertiseRoute.IsValid() {
		if len(rules) > 0 {
			log.Print("warning: PORT_MAP_FILE set but ADVERTISE_ROUTE is empty; no traffic will be intercepted")
		}
		return nil
	}

	lc, err := ts.LocalClient()
	if err != nil {
		return fmt.Errorf("tailscale local client: %w", err)
	}
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:              ipn.Prefs{AdvertiseRoutes: []netip.Prefix{cfg.AdvertiseRoute}},
		AdvertiseRoutesSet: true,
	}); err != nil {
		return fmt.Errorf("advertise route %s: %w", cfg.AdvertiseRoute, err)
	}
	log.Printf("advertised route prefix to tailnet: %s", cfg.AdvertiseRoute)

	if hasTUN() {
		if len(rules) > 0 {
			log.Print("warning: /dev/net/tun present; port-mapping hijack only applies in userspace forwarding mode")
		}
		return nil
	}
	log.Println("no /dev/net/tun; using userspace L4 forwarding")

	return NewSubnetRouter(cfg.AdvertiseRoute, rules, cache).Install(ts)
}

func loadPortRules(cfg *Config) (PortRules, error) {
	if cfg.PortMapFile == "" {
		return nil, nil
	}
	rules, err := LoadPortRules(cfg.PortMapFile)
	if err != nil {
		return nil, fmt.Errorf("load port map %q: %w", cfg.PortMapFile, err)
	}
	log.Printf("loaded %d port-mapping rule(s) from %s", len(rules), cfg.PortMapFile)
	return rules, nil
}

func serveDNS(ts *tsnet.Server, f *Forwarder, addr, upstream string) error {
	dns.HandleFunc(".", f.HandleRequest)

	udpConn, err := ts.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", addr, err)
	}
	tcpLn, err := ts.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", addr, err)
	}

	udpServer := &dns.Server{Addr: addr, Net: "udp", PacketConn: udpConn}
	tcpServer := &dns.Server{Addr: addr, Net: "tcp", Listener: tcpLn}

	errCh := make(chan error, 2)
	go func() { errCh <- udpServer.ActivateAndServe() }()
	go func() { errCh <- tcpServer.ActivateAndServe() }()

	log.Printf("dns forwarder listening on %s (udp/tcp), upstream %s", addr, upstream)

	err = <-errCh
	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()
	return err
}

func hasTUN() bool {
	_, err := os.Stat("/dev/net/tun")
	return err == nil
}
