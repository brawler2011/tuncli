# tuncli

`tuncli` is a minimalist CLI wrapper for `sing-box` to fetch subscriptions and manage VPN connections in TUN or Proxy modes.

## Supported OS

| OS          | Architectures                       | Supported |
| :---------- | :---------------------------------- | :-------: |
| **Linux**   | `x86_64` (amd64), `ARM64` (aarch64) |    Yes    |
| **macOS**   | None                                |    No     |
| **Windows** | None                                |    No     |

## Installation

### Quick Install (Linux x86_64 / ARM64)

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/brawler2011/tuncli/main/install.sh)"
```

### From Source

Install Go (at least the version declared in `go.mod`), GNU Make, and a C
compiler for local builds. Build and install on Linux:

```bash
make build
sudo make install
```

The binary is written to `build/tuncli`. To install without root, use
`make install PREFIX="$HOME/.local"` and add `~/.local/bin` to your `PATH`.
For packaging, `make install DESTDIR=/tmp/tuncli-package` stages the binary at
`/tmp/tuncli-package/usr/local/bin/tuncli`.

## Development

Install golangci-lint (the same version used by CI) and add `$(go env GOPATH)/bin`
to your `PATH`:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
```

```bash
make help       # List available commands
make fmt        # Format Go sources
make lint       # Run golangci-lint, including modernize and testifylint
make check      # Check formatting, run linters and unprivileged tests
make test-guard # Test IPv4/IPv6/DNS leak protection in isolated networks
make test-tun   # Run actual Linux TUN tests in isolated networks
make check-all  # Run check, test-guard and test-tun
make build      # Build locally (also the default for make)
make release    # Create Linux amd64 and arm64 archives in dist/
make clean      # Remove build/ and dist/
```

The linter configuration enables the standard checks (including govet, staticcheck,
errcheck, and unused), plus bodyclose, errorlint, modernize, and testifylint.
Tests use testify: `require` for prerequisites and `assert` for independent checks.

Builds, tests, vet, and linters share the feature tags in the Makefile. CI runs the same
checks and build for pushes and pull requests; tagged releases run checks before
packaging and publishing. Release builds disable CGO and require tar.
The default `make test` suite does not require root or an active VPN connection. If `xray` is installed,
the runner tests also validate generated Xray configuration with it.

`make test-tun` builds a separate Linux test binary with the `tun_smoke` tag and
runs it across two temporary network namespaces connected by a virtual Ethernet
pair. A local Shadowsocks server, UDP DNS resolver, DoH endpoint, HTTP server,
and UDP echo server provide all test traffic; no subscription, VPN credentials,
GitHub downloads, or external Internet access are needed during the test.
The test exercises the production config builder and embedded engine with real
TUN interfaces and kernel sockets. Only DNS endpoint addresses and the fixture's
TLS certificate settings are substituted.

It asserts A/AAAA FakeIP responses over both UDP and TCP DNS, IPv4/IPv6 traffic
capture, TCP/UDP routing through direct versus Shadowsocks paths, personal and
preset priority, both default routes, and real DNS selection. It verifies DNS
resolver paths and data connection sources at the fixture servers, checks source-port reuse across different domain destinations, and reconnects
to saved FakeIPs after restarting the sing-box process **before re-querying those domains**. Failed runs include detailed engine logs.

Requirements: Linux, `/dev/net/tun`, `ip` (iproute2), `unshare` (util-linux),
GNU `timeout`, and either unprivileged user/network namespaces or passwordless
sudo. The script uses user namespaces when available and otherwise runs only
its isolated network setup and test binary through `sudo -n`. Go builds run as
the invoking user. Missing capabilities fail the command; tests are not silently
skipped. Host routes and saved tuncli settings are untouched. Processes, links,
namespaces and scratch files are cleaned up on exit, including test failures;
the run has a hard timeout.

GitHub Actions runs `make test-tun` in a dedicated `ubuntu-24.04` VM job on pushes
and pull requests, and before packaging tagged releases. The workflow checks
TUN availability and loads the module if necessary. An ordinary container runner
must explicitly provide `/dev/net/tun`, network administration capabilities and
permission to create nested network namespaces; a default restricted container
will fail this job. Locally, run `make check-all` for both suites.

Override `GO`, `BUILD_DIR`, or `DIST_DIR` when needed, for example
`make build GO=/path/to/go BUILD_DIR=build/debug`. `make clean` only accepts
directories inside the repository. Build outputs, coverage results, and local
environment files are ignored by Git; `.env.example` can be committed.

---

## Usage

### 1. Update Subscription

Fetch and save nodes from your subscription URL:

```bash
tuncli update "https://your-subscription-url.com/link"
```

To update using the already configured URL:

```bash
tuncli update
```

### 2. Select Node & Mode

Interactively select the connection mode (`tun` or `proxy`) and a server:

```bash
tuncli select
```

### 3. Install the background service

On a systemd Linux laptop, install nftables and prepare the node selection above,
then run once:

```bash
sudo tuncli service install
```

The service imports and validates the calling user's configuration, subscriptions,
HWID and routing cache without modifying the originals. It copies the daemon to
`/usr/local/libexec/tuncli/tuncli` and enables boot-time connection before login.
The service and `/usr/bin/xray` (for XHTTP/SplitHTTP) must have root-owned,
non-user-writable executable paths. Xray is installed separately.

After installation, the owner and root manage the laptop-wide VPN without sudo:

```bash
tuncli status             # State, desired state, node, mode, protection, last error
tuncli status --json
tuncli logs -f
tuncli stop               # Restore internet; stay stopped after reboot
tuncli start              # Connect in background; enable connection after reboot
tuncli restart            # Reconnect; returns an error if stopped
tuncli start --mode proxy --node "My node"
tuncli select             # Save and immediately apply a node/mode selection
```

`start --node/--mode` saves the choice. Duplicate node names are searched in the
selected subscription first. Changes to subscriptions and routing go through the
local API and apply immediately to a running VPN; a stopped VPN stays stopped.
Subscription updates reconnect only when the selected node changes. If that node
disappears, the update fails and preserves the previous subscription.

Both TUN and proxy modes serve a local HTTP/SOCKS5 proxy at `127.0.0.1:2080`
while connected, using the selected node and the same routing rules. In Telegram,
select SOCKS5, set server `127.0.0.1` and port `2080`, and leave username and
password empty. The proxy listens only on this computer and stops with the VPN.
Proxy mode leaves system internet unblocked. Status reports the proxy address.
If the service is unavailable, management
commands return an error. They never start a second VPN.

For a foreground session on Linux without systemd, before installing a service:

```bash
sudo tuncli run                 # TUN; Ctrl+C stops the session
tuncli run --mode proxy         # Does not require root
```

### Protection and recovery

Managed TUN requires nftables. A dedicated `inet tuncli_guard` table protects
IPv4 and IPv6 before TUN creation; a separate early systemd unit runs before
`network-pre.target`. Only loopback, local Linux bridge output, DHCP/IPv6 link maintenance, TUN output,
marked VPN transport and bootstrap DNS to `1.1.1.1:53` and `8.8.8.8:53` (UDP and TCP raced to
avoid stalls when a resolver or transport is blocked) are allowed while connecting.
Configured direct traffic is allowed through the engine only after a successful
HTTPS probe through the VPN. Cloudflare and Google checks run in parallel;
one successful check is sufficient. Initial connection checks allow up to 20 seconds,
including the transport handshake. Health probes run every 10 seconds with a 5-second timeout;
two consecutive failures close direct access and trigger retries with delays
from 1 to 30 seconds. No automatic server selection is performed.

Probe errors identify the VPN server and distinguish the VPN transport handshake
(including TLS/REALITY) from TLS to the probe site and waiting for its HTTP
response. A failed start keeps protection active and schedules a background retry;
it does not immediately repeat the same connection during settings rollback.

Linux bridges are treated as local networks. Host access to Docker containers
and published localhost ports stays available while connecting or reconnecting.
Bridge matching uses the interface kind, so new Docker networks and custom
bridge names work without subnet exceptions or a VPN restart. Forwarding between
bridges is allowed by tuncli; Docker's own firewall still controls network
isolation. Container internet traffic may be forwarded only through TUN, with
established replies allowed back to the bridge. It remains blocked when TUN is
down. This policy assumes the internet-facing interface is not a Linux bridge.

Process crashes and systemd restarts leave protection in the kernel. An explicit
`stop` cancels pending DNS, subscription downloads and connection checks before
persisting the disabled state. Ctrl+C also cancels the client’s pending request.
Closing a managed engine waits for Linux to release its TUN interface before
a subsequent start can reuse it. It closes the engine and Xray, then removes only
tuncli's table. Settings changes are serialized, validated before disconnecting,
and rolled back on launch failure. A transaction journal restores interrupted
settings updates after a crash. Foreign nftables tables are never flushed.

```bash
sudo tuncli service recover     # Persist stopped, stop daemon, remove its rules
sudo tuncli service uninstall   # Also disable/remove units and private executable
```

Uninstall retains `/var/lib/tuncli` as a root-only settings export. Move it to a
backup location before a fresh installation. `recover` is intended for a broken
control socket; ordinary stop requires no sudo.

## Configuration

Before installation, local preparation uses `~/.config/tuncli/config.json` and
subscription caches. With sudo, foreground mode resolves the original user's home.
After installation, `/var/lib/tuncli` is the only active settings source and stores
subscriptions, routing cache and FakeIP database with root-only permissions. The
CLI uses `/run/tuncli/control.sock`; Linux `SO_PEERCRED` restricts operations to the
installation owner and root. There is no remote listener or raw engine-config API.
The owner's UID is recorded in `/etc/tuncli-owner.json`.

macOS, Windows, other init systems in background mode, and per-user VPN isolation
are outside this version. Foreground `run` does not provide the managed nftables
protection described above.

## Split routing

Routing policies are optional. Without an enabled policy, the existing VPN and
DNS behavior is preserved. With the service installed, settings apply immediately
to a running VPN. Before installation, changes are saved for the next foreground run.

```bash
tuncli routing preset list
tuncli routing preset enable ru --outbound direct
tuncli routing preset enable ai --outbound vpn
tuncli routing rule add my.itmo.ru --outbound direct
tuncli routing rule add example.com --suffix --outbound vpn
tuncli routing default vpn
tuncli routing show
tuncli routing update
tuncli routing preset disable ru
tuncli routing rule remove my.itmo.ru
tuncli routing rule remove example.com --suffix
tuncli routing disable
tuncli routing enable
```

Enabling a preset, adding a personal rule, or setting the default enables the
policy. `disable` retains all settings. The initial default is `vpn`; both
`vpn` and `direct` are accepted for every route. `vpn` uses the selected server,
including the Xray sidecar for XHTTP. Presets can be enabled together; omitting
`--outbound` for a preset uses its recommendation.

Rules are evaluated in this order:

1. DNS interception and VPN server connection exceptions.
2. Personal rules: exact domains first, then suffixes from most to least specific.
3. All VPN presets.
4. All direct presets.
5. The explicit default.

Preset enable order has no effect. Suffix rules include the domain itself and
its subdomains. Adding the same domain and rule type replaces its route;
exact and suffix rules can coexist. Domains are lowercased, converted to IDNA,
and stripped of a trailing dot. URLs, IP addresses, wildcards, and invalid
hostnames are rejected; use `--suffix` for subdomains.

Lists come from [SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite),
using its ready-made binary rule sets:

| Preset | Binary file | Recommended route | Coverage |
| --- | --- | --- | --- |
| `ru` | `geosite-category-ru.srs` | `direct` | Broad Russian category, including the entire `.ru` zone |
| `ai` | `geosite-category-ai-!cn.srs` | `vpn` | AI services outside the China category, including Google DeepMind/Gemini |

The source URL is
`https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/`.
Upstream has a [daily build](https://github.com/SagerNet/sing-geosite/blob/main/.github/workflows/release.yaml).
Membership can change upstream; tuncli does not maintain a separate domain database.
`routing show` reports routes, source URLs, verification times, hashes, and cache state.

With an active TUN policy, the gVisor stack keeps connections to different
domains separate when clients reuse a source port. Builds must include
`with_gvisor`, as all Makefile and release builds do. A checked-in patch to
`sing v0.8.10` keys UDP NAT by both source and destination, preventing a socket
sending to several domains from inheriting its first route. Patch provenance
and changed files are documented in `third_party/sing/TUNCLI_PATCH.md`.
Client DNS A/AAAA requests receive FakeIP addresses
from `198.18.0.0/15` and `fc00::/18`. The TUN interface also captures IPv6.
TCP and UDP DNS on port 53 are intercepted. sing-box restores the domain before
routing and resolves real addresses with the same ordered policy: direct domains
use a direct UDP resolver at `1.1.1.1`, VPN domains use Cloudflare DoH through the
VPN. DNS final follows the policy default. VPN server bootstrap remains direct.
Internal lookups skip FakeIP, and resolver caches are independent. FakeIP mappings
persist in `/var/lib/tuncli/routing/fakeip.db` for the service (or
`~/.config/tuncli/routing/fakeip.db` in foreground mode) across normal restarts.

Proxy mode does not enable FakeIP; rules apply to domain names supplied by HTTP
or SOCKS clients. Applications using their own DoH or known IP addresses may
bypass domain matching. For predictable TUN routing, configure applications to
use system DNS intercepted by tuncli, and disable their private DNS/DoH.

Verified lists and metadata are stored in `~/.config/tuncli/routing/`, under the
original user's home for foreground mode; managed mode uses
`/var/lib/tuncli/routing/`. Settings are written atomically, and
files created through privilege elevation remain accessible to that user.
At startup, enabled lists older than 24 hours are refreshed over HTTPS with a
20-second timeout and 16 MiB size limit. Files are parsed and checked by the
pinned sing-box version before publication. Updates are locked and atomic;
binary paths contain SHA-256 hashes, so an update does not replace a running
process's list. No background refresh changes a running connection.

If refresh fails, startup warns and uses the last verified copy. With no valid
copy, startup fails before creating TUN. `routing update` forces refresh of all
configured presets (even while the policy is disabled), returns a nonzero status
on any failure, and reports retained copies. Restore network access and retry
`routing update`; `routing disable` temporarily restores the original routing.
Old hash files are retained for running processes; remove unused copies only
while all tuncli instances are stopped.

### Manual Linux TUN smoke test

On a Linux host with working IPv4/IPv6 and a selected VPN node:

1. Enable `ru -> direct`, `ai -> vpn`, `my.itmo.ru -> direct`, and default `vpn`.
   Run `tuncli routing update`, then `tuncli start`.
2. Check `ip address show tuncli-tun0` for IPv4 and IPv6. Query A and AAAA using
   system DNS for `ozon.ru`, `gosuslugi.ru`, `gemini.google.com`, and `my.itmo.ru`;
   expect FakeIP ranges. Repeat a DNS query over TCP (`dig +tcp`).
3. With application private DNS disabled, connect to these domains. Use packet
   capture on the physical interface to verify direct connections for Russian
   domains and ITMO, and the VPN connection for Gemini and unknown domains.
   Verify direct DNS uses UDP/53, while VPN DNS travels inside the VPN.
4. Stop normally, restart, and verify previously returned FakeIPs still recover
   their domains. Repeat with default `direct`, and with an XHTTP node if available.
5. Make an enabled list stale, block list downloads, and restart: expect a warning
   and cached rules. With no verified copy, expect failure before TUN creation.
   Restore downloads and run `routing update` to recover.
6. Disable the policy and restart. Confirm the original DNS and routing behavior.
   Test proxy mode separately with `curl --socks5-hostname 127.0.0.1:2080 ...`.

## Service verification

`make test-guard` uses isolated network namespaces and local TCP/UDP fixtures to
check IPv4/IPv6 and DNS blocking, separate transport/direct/bootstrap marks,
direct access only while connected, persistence after SIGKILL, foreign-table
preservation and internet restoration after stop. It also checks new Docker-like
bridges, host and inter-container access, localhost port publishing, container
TCP/UDP over a real TUN, the local SOCKS5 proxy, downstream network isolation,
and blocked container internet after TUN closes. It needs nftables, iproute2,
util-linux, `/dev/net/tun`, and user/network namespaces or passwordless sudo.
No external internet is needed. `make check-all` includes these checks and the existing real
TUN routing suite. See [the systemd VM checklist](docs/systemd-vm.md) for the
boot/login, cgroup, ownership and recovery acceptance checks.
