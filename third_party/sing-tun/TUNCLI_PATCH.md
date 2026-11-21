# tuncli dependency patch

This directory contains `github.com/sagernet/sing-tun
v0.8.10-0.20260603023501-3b51857024d0`, copied from the Go module cache.
Upstream source and license are retained. Only `tun_linux.go` is modified.

In `NativeTun.rules`, place the source-bound IPv6 TUN subnet lookup before
local IPv6 source bypasses, while keeping packets arriving from TUN exempt.
Previously `::/1` and `8000::/1` bypasses shadowed the TUN source rule.
Linux initially chooses a TUN source for an unbound socket, but after OpenSSH
changes IPV6_TCLASS, its route-cache invalidation triggers a lookup with that
source already set. The bypass then skips the TUN table: the connection stalls
or escapes capture if another IPv6 route exists.

No DNS, domain routing, transport, or public API changes are needed.
The root module replaces the dependency with this source for reproducible builds.
`pkg/runner/tun_smoke_test.go` tests EF -> CS0 -> EF changes on established
IPv4 and IPv6 TCP connections through both direct and VPN routes.
Keep this regression test when replacing the patch with an upstream fix.
