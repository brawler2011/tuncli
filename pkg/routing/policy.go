// Package routing defines the persisted domain routing policy and verified rule cache.
package routing

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

type Outbound string

const (
	Direct Outbound = "direct"
	VPN    Outbound = "vpn"
)

func (o Outbound) Validate() error {
	if o != Direct && o != VPN {
		return fmt.Errorf("invalid outbound %q: use direct or vpn", o)
	}
	return nil
}
func (o Outbound) Tag() string {
	if o == VPN {
		return "proxy"
	}
	return "direct"
}
func (o Outbound) DNS() string {
	if o == VPN {
		return "dns-remote"
	}
	return "dns-local"
}

type Rule struct {
	Domain   string   `json:"domain"`
	Suffix   bool     `json:"suffix,omitempty"`
	Outbound Outbound `json:"outbound"`
}
type Policy struct {
	Enabled bool                `json:"enabled"`
	Default Outbound            `json:"default"`
	Presets map[string]Outbound `json:"presets,omitempty"`
	Rules   []Rule              `json:"rules,omitempty"`
}
type Preset struct {
	ID, File    string
	Recommended Outbound
}

var Presets = []Preset{{"ru", "geosite-category-ru.srs", Direct}, {"ai", "geosite-category-ai-!cn.srs", VPN}}

const BaseURL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/"

func Find(id string) (Preset, error) {
	for _, p := range Presets {
		if p.ID == id {
			return p, nil
		}
	}
	return Preset{}, fmt.Errorf("unknown routing preset %q (available: ru, ai)", id)
}
func New() *Policy { return &Policy{Default: VPN, Presets: map[string]Outbound{}} }
func Normalize(s string) (string, error) {
	original := s
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	a, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", original, err)
	}
	if len(a) == 0 || len(a) > 253 || net.ParseIP(a) != nil {
		return "", fmt.Errorf("invalid domain %q", original)
	}
	for label := range strings.SplitSeq(a, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain %q", original)
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("invalid domain %q: use --suffix for subdomains", original)
			}
		}
	}
	return a, nil
}
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	if err := p.Default.Validate(); err != nil {
		return err
	}
	for id, o := range p.Presets {
		if _, err := Find(id); err != nil {
			return err
		}
		if err := o.Validate(); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		d, err := Normalize(r.Domain)
		if err != nil {
			return err
		}
		r.Domain = d
		if err = r.Outbound.Validate(); err != nil {
			return err
		}
		key := fmt.Sprintf("%t:%s", r.Suffix, d)
		if seen[key] {
			return fmt.Errorf("duplicate domain rule %s", d)
		}
		seen[key] = true
	}
	return nil
}

// Entry is shared by route and real-DNS generation, in precedence order.
type Entry struct {
	Match    map[string]any
	Outbound Outbound
}
type Prepared struct {
	ServerIPs  []string
	Policy     *Policy
	Paths      map[string]string
	FakeIPPath string
}

func (p *Prepared) Entries() []Entry {
	rules := append([]Rule(nil), p.Policy.Rules...)
	sort.Slice(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Suffix != b.Suffix {
			return !a.Suffix
		}
		if len(a.Domain) != len(b.Domain) {
			return len(a.Domain) > len(b.Domain)
		}
		return a.Domain < b.Domain
	})
	var result []Entry
	for _, r := range rules {
		key := "domain"
		if r.Suffix {
			key = "domain_suffix"
		}
		result = append(result, Entry{map[string]any{key: []string{r.Domain}}, r.Outbound})
	}
	for _, o := range []Outbound{VPN, Direct} {
		for _, preset := range Presets {
			if p.Policy.Presets[preset.ID] == o {
				result = append(result, Entry{map[string]any{"rule_set": []string{"preset-" + preset.ID}}, o})
			}
		}
	}
	return result
}
