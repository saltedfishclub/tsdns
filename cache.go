package main

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// minCacheTTL bounds how quickly an entry can expire. Upstreams sometimes
// hand out very short TTLs; since the cache exists so that inbound connections
// can be matched back to the name that produced them, we keep entries around
// at least this long to avoid races between a client's DNS lookup and its
// immediately-following connection.
const minCacheTTL = 30 * time.Second

// ResolveCache remembers the IPs that recently-answered DNS queries resolved
// to, keyed by the (client-facing) question name. The DNS forwarder populates
// it as it answers; the subnet router reads it to map a hijack rule's domain
// back to the IPs a connection might target.
type ResolveCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	now     func() time.Time // overridable for tests
}

type cacheEntry struct {
	ips     []netip.Addr
	expires time.Time
}

// NewResolveCache returns an empty cache.
func NewResolveCache() *ResolveCache {
	return &ResolveCache{
		entries: make(map[string]cacheEntry),
		now:     time.Now,
	}
}

// Put records that name resolved to ips, valid for ttl. A zero or negative ttl
// (or one below minCacheTTL) is clamped to minCacheTTL. Empty IP sets are
// ignored so a NODATA answer never evicts a good entry.
func (c *ResolveCache) Put(name string, ips []netip.Addr, ttl time.Duration) {
	if len(ips) == 0 {
		return
	}
	if ttl < minCacheTTL {
		ttl = minCacheTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[canonicalName(name)] = cacheEntry{
		ips:     ips,
		expires: c.now().Add(ttl),
	}
}

// Lookup returns the currently-cached IPs for name, or nil if there is no
// unexpired entry.
func (c *ResolveCache) Lookup(name string) []netip.Addr {
	key := canonicalName(name)

	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	if !c.now().Before(e.expires) {
		// Expired: drop it lazily so the map does not grow unbounded.
		c.mu.Lock()
		if cur, ok := c.entries[key]; ok && cur.expires.Equal(e.expires) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return nil
	}
	return e.ips
}

// canonicalName normalizes a DNS name for use as a cache key: lower-cased and
// fully-qualified with a trailing dot.
func canonicalName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name != "" && !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// addrFromIP converts a net.IP (as found in A/AAAA records) to a normalized
// netip.Addr, unmapping IPv4-in-IPv6 so comparisons are consistent.
func addrFromIP(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}
