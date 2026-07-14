package main

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Config is the fully-parsed, validated runtime configuration, sourced
// entirely from environment variables.
type Config struct {
	// Tailscale node settings.
	Hostname   string // TS_HOSTNAME
	StateDir   string // TS_STATE_DIR
	PreferPort uint16 // TS_PREFER_PORT (0 = let tsnet choose)
	Verbose    bool   // TS_VERBOSE

	// Homelab DNS naming: "<service>.<project>.<zone><tld>" resolves to a
	// container, and "<zone><tld>" resolves to this node itself.
	HomelabZone string // HOMELAB_ZONE, normalized (lowercase, no surrounding dots)
	LocalTLD    string // HOMELAB_TLD, normalized with a leading dot, e.g. ".lan"

	// Subnet routing.
	AdvertiseRoute netip.Prefix // ADVERTISE_ROUTE; zero value means "no route"
	PortMapFile    string       // PORT_MAP_FILE; empty means "no hijack rules"
}

// SelfZone returns the fully-qualified name that resolves to this node,
// e.g. "homelab.lan.".
func (c *Config) SelfZone() string {
	return c.HomelabZone + c.LocalTLD + "."
}

// LoadConfig reads and validates the configuration from the environment.
func LoadConfig() (*Config, error) {
	verbose, err := envBool("TS_VERBOSE", false)
	if err != nil {
		return nil, err
	}

	zone := strings.Trim(strings.ToLower(envOr("HOMELAB_ZONE", "homelab")), ".")
	if zone == "" {
		return nil, fmt.Errorf("HOMELAB_ZONE must not be empty")
	}

	tld := envOr("HOMELAB_TLD", "local")
	if !strings.HasPrefix(tld, ".") {
		tld = "." + tld
	}

	preferPort, err := envPort("TS_PREFER_PORT")
	if err != nil {
		return nil, err
	}

	route, err := envPrefix("ADVERTISE_ROUTE")
	if err != nil {
		return nil, err
	}

	return &Config{
		Hostname:       envOr("TS_HOSTNAME", "tsdns"),
		StateDir:       envOr("TS_STATE_DIR", ""),
		PreferPort:     preferPort,
		Verbose:        verbose,
		HomelabZone:    zone,
		LocalTLD:       tld,
		AdvertiseRoute: route,
		PortMapFile:    envOr("PORT_MAP_FILE", ""),
	}, nil
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid %s=%q: %w", key, v, err)
	}
	return b, nil
}

func envPort(key string) (uint16, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return 0, nil
	}
	p, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid %s=%q: %w", key, v, err)
	}
	return uint16(p), nil
}

func envPrefix(key string) (netip.Prefix, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return netip.Prefix{}, nil
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid %s=%q: %w", key, v, err)
	}
	return p, nil
}
