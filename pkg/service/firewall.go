package service

import (
	"fmt"
	"os/exec"
	"strings"
)

// Only this inet table belongs to tuncli. Updates are atomic nft transactions.
const Table = "tuncli_guard"

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
	return nil
}
func Rules(direct bool) string {
	allowDirect := ""
	if direct {
		allowDirect = "add rule inet tuncli_guard output meta mark 355 accept\n"
	}
	return `add chain inet tuncli_guard output { type filter hook output priority -150; policy drop; }
add rule inet tuncli_guard output oifname "lo" accept
add rule inet tuncli_guard output oifname "tuncli-tun0" accept
add rule inet tuncli_guard output udp sport 68 udp dport 67 accept
add rule inet tuncli_guard output udp sport 546 udp dport 547 ip6 daddr ff02::1:2 accept
add rule inet tuncli_guard output meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } ip6 hoplimit 255 accept
add rule inet tuncli_guard output meta mark 354 accept
add rule inet tuncli_guard output meta mark 356 ip daddr 1.1.1.1 udp dport 53 accept
` + allowDirect + `add chain inet tuncli_guard forward { type filter hook forward priority -150; policy drop; }
`
}
func (NFT) Remove() error {
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
