# tsdns

tsdns act as a recursive dns server that transforms DNS requests to match corresponding docker containers. It can also advertise a subnet to route traffics into docker network.

Docker containers are supposed to be used with.

## Example Usage

```yaml
services:
  server:
    image: ghcr.io/saltedfishclub/tsdns:latest
    user: "1000:1000"
    environment:
      TS_AUTHKEY: "tskey-auth-......"
      HOMELAB_TLD: "lan"
      HOMELAB_ZONE: "homelab"
      TS_HOSTNAME: "tsdns-homelab"
      TS_STATE_DIR: "/ts-state"
      ADVERTISE_ROUTE: "10.1.0.0/27"
    networks: [published]
    volumes:
      - "./state:/ts-state"
#    restart: unless-stopped
    restart: no
networks:
  published:
    name: published
    ipam:
      driver: default
      config:
        - subnet: 10.1.0.0/24
          ip_range: 10.1.0.0/27
```

Assuming that tailscale has assigned 100.64.0.1 to this tsnet instance, and another container `web-caddy-1` has joined network `web` and `published`. Then the following command resolves web-caddy-1's ip:

```
$ dig @100.64.0.1 +short caddy.web.homelab.lan
10.1.0.3
```

With proper dns setup, you can visit that caddy over browser directly.

## Port mapping (connection hijacking)

While acting as a subnet router, tsdns observes every TCP/UDP flow the tailnet
routes into the advertised subnet. With a port-mapping file you can hijack
selected flows and relay them to a different destination.

Set `PORT_MAP_FILE` to a file whose lines are:

```
<original-dest> <original-port> <rewritten-dest> <rewritten-port>
```

* `original-dest` and `rewritten-dest` may each be a literal IP or a domain.
* Blank lines and lines starting with `#` are ignored.
* A rule applies to both TCP and UDP; the first matching rule wins.

When `original-dest` is a domain, it is matched against the IPs that domain
most recently resolved to *through tsdns itself* (its answer cache). So a client
that looks up `caddy.web.homelab.lan` and then connects is transparently
redirected:

```
# redirect caddy's HTTP to an internal backend
caddy.web.homelab.lan 80 10.1.0.9 8080

# redirect a fixed subnet IP to another host:port
10.1.0.3 443 secure.internal 8443
```

`rewritten-dest` is dialed from tsdns: a literal IP is used directly, and a
domain is resolved via the answer cache when known, otherwise by the host
resolver.

> Port mapping is only active in userspace forwarding mode (i.e. when
> `/dev/net/tun` is absent, as in the unprivileged container above), the same
> mode used for subnet routing.

Add it to the compose example with a mounted file:

```yaml
    environment:
      # ...existing vars...
      PORT_MAP_FILE: "/config/portmap"
    volumes:
      - "./state:/ts-state"
      - "./portmap:/config/portmap:ro"
```