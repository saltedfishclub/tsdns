package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"tailscale.com/tsnet"
	"tailscale.com/types/nettype"
	"tailscale.com/wgengine/netstack"
)

const (
	dialTimeout    = 10 * time.Second
	udpIdleTimeout = 2 * time.Minute
	maxUDPPayload  = 64 * 1024
)

// SubnetRouter forwards tailnet traffic routed to the advertised subnet. For
// flows matching a port-mapping rule it hijacks the connection and relays it to
// the rewritten destination; everything else in the subnet is handed to
// gVisor's built-in userspace forwarder to reach its original destination.
type SubnetRouter struct {
	prefix netip.Prefix
	rules  PortRules
	cache  *ResolveCache
	dialer net.Dialer
}

// NewSubnetRouter returns a router for the advertised prefix. rules may be empty,
// in which case the router only performs plain subnet forwarding.
func NewSubnetRouter(prefix netip.Prefix, rules PortRules, cache *ResolveCache) *SubnetRouter {
	return &SubnetRouter{
		prefix: prefix,
		rules:  rules,
		cache:  cache,
		dialer: net.Dialer{Timeout: dialTimeout},
	}
}

// Install wires the router's per-flow handlers into the tsnet server's netstack.
// It must be called after the server is up.
func (r *SubnetRouter) Install(ts *tsnet.Server) error {
	ns, err := netstackImpl(ts)
	if err != nil {
		return err
	}
	oldTCP := ns.GetTCPHandlerForFlow
	oldUDP := ns.GetUDPHandlerForFlow

	ns.GetTCPHandlerForFlow = func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		if r.prefix.Contains(dst.Addr()) {
			if rule, ok := r.match(dst); ok {
				return func(c net.Conn) { r.hijackTCP(c, rule) }, true
			}
			return nil, false // use gVisor's built-in forwardTCP to the real dest
		}
		if oldTCP != nil {
			return oldTCP(src, dst) // node-local listeners, tailnet services, etc.
		}
		return nil, false
	}

	ns.GetUDPHandlerForFlow = func(src, dst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
		if r.prefix.Contains(dst.Addr()) {
			if rule, ok := r.match(dst); ok {
				return func(c nettype.ConnPacketConn) { r.hijackUDP(c, rule) }, true
			}
			return nil, false // use gVisor's built-in forwardUDP to the real dest
		}
		if oldUDP != nil {
			return oldUDP(src, dst) // node-local listeners, tailnet services, etc.
		}
		return nil, false
	}

	log.Printf("subnet router installed for %s (%d port-mapping rule(s))", r.prefix, len(r.rules))
	return nil
}

func (r *SubnetRouter) match(dst netip.AddrPort) (PortRule, bool) {
	if len(r.rules) == 0 {
		return PortRule{}, false
	}
	return r.rules.Match(dst, r.cache.Lookup)
}

// targetAddr renders a rule's rewritten destination as a host:port string,
// resolving a domain target through the cache when possible so synthetic
// homelab names still work; otherwise the OS resolver handles it at dial time.
func (r *SubnetRouter) targetAddr(rule PortRule) string {
	host := rule.TargetHost
	if _, err := netip.ParseAddr(host); err != nil {
		if ips := r.cache.Lookup(host); len(ips) > 0 {
			host = ips[0].String()
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(int(rule.TargetPort)))
}

func (r *SubnetRouter) hijackTCP(client net.Conn, rule PortRule) {
	defer client.Close()

	addr := r.targetAddr(rule)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	target, err := r.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Printf("port-map: dial tcp %s (from %s) failed: %v", addr, rule.Source(), err)
		return
	}
	defer target.Close()

	log.Printf("port-map: hijack tcp %s -> %s", rule.Source(), addr)
	proxyTCP(client, target)
}

func (r *SubnetRouter) hijackUDP(client nettype.ConnPacketConn, rule PortRule) {
	addr := r.targetAddr(rule)

	target, err := net.Dial("udp", addr)
	if err != nil {
		log.Printf("port-map: dial udp %s (from %s) failed: %v", addr, rule.Source(), err)
		_ = client.Close()
		return
	}

	log.Printf("port-map: hijack udp %s -> %s", rule.Source(), addr)
	proxyUDP(client, target) // takes ownership of closing both conns
}

// proxyTCP relays bytes in both directions until both halves close.
func proxyTCP(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyAndHalfClose(a, b) }()
	go func() { defer wg.Done(); copyAndHalfClose(b, a) }()
	wg.Wait()
}

func copyAndHalfClose(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	// Signal EOF to the peer so its copy direction can drain and finish.
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}
}

// proxyUDP relays datagrams in both directions, tearing the session down after
// udpIdleTimeout of inactivity. It closes both conns before returning.
func proxyUDP(client, target net.Conn) {
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			_ = client.Close()
			_ = target.Close()
		})
	}
	idle := time.AfterFunc(udpIdleTimeout, shutdown)
	defer idle.Stop()

	pump := func(dst, src net.Conn) {
		defer shutdown()
		buf := make([]byte, maxUDPPayload)
		for {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
			idle.Reset(udpIdleTimeout)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pump(target, client) }()
	go func() { defer wg.Done(); pump(client, target) }()
	wg.Wait()
}

// netstackImpl reaches into tsnet.Server for its unexported *netstack.Impl so
// per-flow forwarding handlers can be installed. tsnet exposes no public API
// for this, hence the reflect/unsafe access; it is guarded by the field's
// presence and only valid against the pinned tailscale version.
func netstackImpl(s *tsnet.Server) (*netstack.Impl, error) {
	v := reflect.ValueOf(s).Elem().FieldByName("netstack")
	if !v.IsValid() {
		return nil, fmt.Errorf("tsnet.Server has no netstack field (tailscale version mismatch?)")
	}
	ns := (*netstack.Impl)(unsafe.Pointer(v.Pointer()))
	if ns == nil {
		return nil, fmt.Errorf("tsnet netstack not initialized (Install must run after Server.Up)")
	}
	return ns, nil
}
