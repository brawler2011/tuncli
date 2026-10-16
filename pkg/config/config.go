package config

import (
	"encoding/json"
	"fmt"
	"github.com/brawler2011/tuncli/pkg/routing"
	"github.com/brawler2011/tuncli/pkg/storage"
	"os"
	"os/user"
	"path/filepath"
)

type SubscriptionItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	Type string `json:"type"` // "subscription" or "server"
}

type Config struct {
	Routing              *routing.Policy    `json:"routing,omitempty"`
	Mode                 string             `json:"mode"`
	SelectedSubscription string             `json:"selected_subscription"` // ID of the subscription/server
	SelectedNode         string             `json:"selected_node"`         // Name of the node
	Subscriptions        []SubscriptionItem `json:"subscriptions"`

	// Legacy fields kept for migration
	SubscriptionURL   string `json:"subscription_url,omitempty"`
	SelectedNodeIndex int    `json:"selected_node_index,omitempty"`
	Nodes             []Node `json:"nodes,omitempty"`
}

type Node struct {
	Name      string         `json:"name"`
	Protocol  string         `json:"protocol"`
	Server    string         `json:"server"`
	Port      int            `json:"port"`
	RawLink   string         `json:"raw_link"`   // For URI lists
	RawConfig map[string]any `json:"raw_config"` // For YAML/JSON formats
}

// Directory is set only by the privileged daemon, before serving requests.
// Callers serialize changes while preparing a transaction.
var Directory string

func GetConfigDir() (string, error) {
	if Directory != "" {
		return Directory, nil
	}
	home := getHomeDir()
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	}
	dir := filepath.Join(home, ".config", "tuncli")
	if err := storage.Mkdir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func GetConfigPath() (string, error) {
	dir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func GetSubscriptionsDir() (string, error) {
	dir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	subDir := filepath.Join(dir, "subscriptions")
	if err := storage.Mkdir(subDir); err != nil {
		return "", err
	}
	return subDir, nil
}

func GetSubscriptionPath(id string) (string, error) {
	if id == "" || filepath.Base(id) != id || id == "." || id == ".." {
		return "", fmt.Errorf("invalid subscription ID")
	}
	dir, err := GetSubscriptionsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, id+".json"), nil
}

func LoadSubscriptionNodes(id string) ([]Node, error) {
	path, err := GetSubscriptionPath(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Node{}, nil
		}
		return nil, err
	}
	var nodes []Node
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

func SaveSubscriptionNodes(id string, nodes []Node) error {
	path, err := GetSubscriptionPath(id)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}
	return storage.Write(path, data)
}

func DeleteSubscriptionNodes(id string) error {
	path, err := GetSubscriptionPath(id)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func LoadConfig() (*Config, error) {
	path, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{
				Mode:                 "tun",
				SelectedSubscription: "",
				SelectedNode:         "",
				Subscriptions:        []SubscriptionItem{},
			}, nil
		}
		return nil, err
	}

	var cfg Config
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	if err := cfg.Routing.Validate(); err != nil {
		return nil, fmt.Errorf("routing: %w", err)
	}

	// Migrate legacy config if needed
	if cfg.SubscriptionURL != "" || len(cfg.Nodes) > 0 {
		err = migrateConfig(&cfg)
		if err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}

func migrateConfig(cfg *Config) error {
	subID := "sub1"

	subItem := SubscriptionItem{
		ID:   subID,
		Name: "Default",
		URL:  cfg.SubscriptionURL,
		Type: "subscription",
	}
	if subItem.URL == "" {
		subItem.Type = "server"
	}

	err := SaveSubscriptionNodes(subID, cfg.Nodes)
	if err != nil {
		return err
	}

	cfg.Subscriptions = append(cfg.Subscriptions, subItem)
	cfg.SelectedSubscription = subID

	if cfg.SelectedNodeIndex >= 0 && cfg.SelectedNodeIndex < len(cfg.Nodes) {
		cfg.SelectedNode = cfg.Nodes[cfg.SelectedNodeIndex].Name
	}

	// Clean up legacy fields
	cfg.SubscriptionURL = ""
	cfg.SelectedNodeIndex = -1
	cfg.Nodes = nil

	return SaveConfig(cfg)
}

func SaveConfig(cfg *Config) error {
	if err := cfg.Routing.Validate(); err != nil {
		return fmt.Errorf("routing: %w", err)
	}
	path, err := GetConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return storage.Write(path, data)
}

func getHomeDir() string {
	// When run with sudo, use the original user's home
	for _, env := range []string{"SUDO_USER", "DOAS_USER"} {
		if username := os.Getenv(env); username != "" {
			u, err := user.Lookup(username)
			if err == nil {
				return u.HomeDir
			}
		}
	}
	// Fallback to HOME env or UserHomeDir
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	return ""
}
