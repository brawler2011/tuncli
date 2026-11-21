package service

import (
	"fmt"
	"os/exec"
	"strings"
)

// Only this inet table belongs to tuncli. Updates are atomic nft transactions.
const Table = "tuncli_guard"

// IPv4 DNS between ports of one local bridge (Kubernetes pods querying cluster
// DNS) carries this mark; the rule sends it to the main table ahead of sing-tun's
// rules at 9000, which would hijack it into TUN. IPv6 is not covered: fib6 lookups
// through sing-tun's rules do not see the bridge route.
const (
	localDNSMark = "0x00100000"
	localDNSRule = "8999"
)

type Firewall interface {
	Apply(direct bool) error
	Remove() error
}
type NFT struct{}

func (NFT) Apply(direct bool) error {
	script := "add table inet " + Table + "\nflush table inet " + Table + "\n" + Rules(direct)
	cmd := exec.Command("/usr/sbin/nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nftables protection: %w: %s", err, b)
	}
	return localDNSRoute(true)
}

func localDNSRoute(add bool) error {
	for exec.Command("/usr/sbin/ip", "-4", "rule", "del", "pref", localDNSRule).Run() == nil {
	}
	if !add {
		return nil
	}
	b, err := exec.Command("/usr/sbin/ip", "-4", "rule", "add", "pref", localDNSRule, "fwmark", localDNSMark+"/"+localDNSMark, "lookup", "main", "suppress_prefixlength", "0").CombinedOutput()
	if err != nil {
		return fmt.Errorf("local DNS route: %w: %s", err, b)
	}
	return nil
}
func Rules(direct bool) string {
	// Local Linux bridges remain usable, including bridges created after start.
	// Forwarded internet traffic must still use TUN. Accept here does not skip
	// Docker's later filter chains, which retain port and network isolation.
	allowDirect := ""
	if direct {
		allowDirect = "add rule inet tuncli_guard output meta mark 355 accept\n"
	}
	return `add chain inet tuncli_guard output { type filter hook output priority -150; policy drop; }
add rule inet tuncli_guard output oifname "lo" accept
add rule inet tuncli_guard output oifname "tuncli-tun0" accept
add rule inet tuncli_guard output meta oifkind "bridge" accept
add rule inet tuncli_guard output udp sport 68 udp dport 67 accept
add rule inet tuncli_guard output udp sport 546 udp dport 547 ip6 daddr ff02::1:2 accept
add rule inet tuncli_guard output meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } ip6 hoplimit 255 accept
add rule inet tuncli_guard output meta mark 354 accept
add rule inet tuncli_guard output meta mark 356 ip daddr { 1.1.1.1, 8.8.8.8 } meta l4proto { tcp, udp } th dport 53 accept
` + allowDirect + `add chain inet tuncli_guard forward { type filter hook forward priority -150; policy drop; }
add rule inet tuncli_guard forward meta iifkind "bridge" meta oifkind "bridge" accept
add rule inet tuncli_guard forward meta iifkind "bridge" oifname "tuncli-tun0" accept
add rule inet tuncli_guard forward iifname "tuncli-tun0" meta oifkind "bridge" ct state established,related accept
` +
		// Priority -90 follows Kubernetes service DNAT, so daddr is already the pod.
		`add chain inet tuncli_guard prerouting { type filter hook prerouting priority -90; policy accept; }
add rule inet tuncli_guard prerouting meta nfproto ipv4 meta iifkind "bridge" meta l4proto { tcp, udp } th dport 53 fib daddr . iif oif exists meta mark set meta mark | ` + localDNSMark + `
`
}
func (NFT) Remove() error {
	if err := localDNSRoute(false); err != nil {
		return err
	}
	// delete is intentionally scoped; ENOENT is accepted only after checking absence.
	cmd := exec.Command("/usr/sbin/nft", "delete", "table", "inet", Table)
	if b, err := cmd.CombinedOutput(); err != nil {
		if tables, check := exec.Command("/usr/sbin/nft", "list", "tables").Output(); check == nil {
			if !strings.Contains(string(tables), "table inet "+Table+"\n") {
				return nil
			}
		}
		return fmt.Errorf("remove protection: %w: %s", err, b)
	}
	return nil
}
