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