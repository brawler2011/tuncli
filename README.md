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

Ensure Go is installed, then build and install:

```bash
make build
sudo make install
```

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

> [!IMPORTANT]
> Running in **TUN** mode requires root privileges (`sudo`) to configure the virtual network interface. **Proxy** mode can be run as a regular user.

---

## Configuration

Settings are stored at:

- `~/.config/tuncli/config.json`

> [!NOTE]
> When run with `sudo` or `doas`, `tuncli` automatically resolves the original user (`SUDO_USER` / `DOAS_USER`) to read and write config files from/to their home directory rather than the root user's home.
