# tuncli dependency patch

This directory contains the source of `github.com/sagernet/sing v0.8.10`, copied
from the Go module cache. Upstream license and source files are retained.

Only `common/udpnat2/service.go` and `common/udpnat2/conn.go` are modified:

- Include destination address and port in the UDP NAT session key. Looking up
  by source alone conflates independent destinations from one socket and can
  reuse a DNS-interception session for application data, or a direct route for
  a VPN domain.
- Hold the handler read lock until a packet is queued, preventing SetHandler
  from draining the queue before the first packet is inserted. Release the lock
  before invoking an installed handler.
- Keep the key and cache on each connection so timeout inspection/updates affect
  the correct session.

The public API is unchanged. The root go.mod replaces the pinned module with
this checked-in source to make builds and release archives reproducible.

Regression coverage lives in `pkg/runner`: a low-level UDP NAT test plus the real
TUN test sending to both direct and VPN domains from the same UDP socket.
Remove this replacement when a compatible upstream version provides equivalent
full-destination session isolation; retain the regression tests when upgrading.
