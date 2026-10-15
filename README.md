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

```bash
make help       # List available commands
make fmt        # Format Go sources
make check      # Check formatting, run go vet and tests
make build      # Build locally (also the default for make)
make release    # Create Linux amd64 and arm64 archives in dist/
make clean      # Remove build/ and dist/
```

Builds, tests, and vet share the feature tags in the Makefile. CI runs the same
checks and build for pushes and pull requests; tagged releases run checks before
packaging and publishing. Release builds disable CGO and require tar.
Tests do not require root or an active VPN connection. If `xray` is installed,
the runner tests also validate generated Xray configuration with it.

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

### 3. Start VPN

Start the connection:

```bash
sudo tuncli start
```

For a single launch, override the mode or select a node by its exact name:

```bash
tuncli start --mode proxy --node "My node"
```

These flags do not change the saved selection. If names repeat, the selected
subscription is searched first, then the other subscriptions in saved order.
Proxy mode listens on `127.0.0.1:2080` (HTTP and SOCKS).

Stop the connection from another terminal using the same user and privilege
level as `start`:

```bash
sudo tuncli stop  # For a connection started with sudo
# tuncli stop     # For a connection started as a regular user
```

Only one instance per effective user can run at a time. Runtime state is locked
in `/tmp/tuncli-<effective-uid>/` with private permissions. Stopping requires
Linux pidfd support (kernel 5.3 or newer); Ctrl+C also stops the foreground process.

XHTTP and SplitHTTP nodes require an external `xray` executable, installed at
`/usr/bin/xray` or available in `PATH`. Other transports use the embedded sing-box
engine. Xray starts and stops with the VPN; it is not bundled in release archives.

> [!IMPORTANT]
> Running in **TUN** mode requires root privileges (`sudo`) to configure the virtual network interface. **Proxy** mode can be run as a regular user.

---

## Configuration

Settings are stored at:

- `~/.config/tuncli/config.json`

> [!NOTE]
> When run with `sudo` or `doas`, `tuncli` automatically resolves the original user (`SUDO_USER` / `DOAS_USER`) to read and write config files from/to their home directory rather than the root user's home.
