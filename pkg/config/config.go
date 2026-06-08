package config

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
)

type Config struct {
	SubscriptionURL   string `json:"subscription_url"`
	Mode              string `json:"mode"`                // "tun" or "proxy"
	SelectedNodeIndex int    `json:"selected_node_index"` // -1 for none
	Nodes             []Node `json:"nodes"`
}

type Node struct {
	Name      string                 `json:"name"`
	Protocol  string                 `json:"protocol"`
	Server    string                 `json:"server"`
	Port      int                    `json:"port"`
	RawLink   string                 `json:"raw_link"`   // For URI lists
	RawConfig map[string]interface{} `json:"raw_config"` // For YAML/JSON formats
}

func GetConfigDir() (string, error) {
	home := getHomeDir()
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	}
	dir := filepath.Join(home, ".config", "tuncli")
	if err := os.MkdirAll(dir, 0755); err != nil {
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

func LoadConfig() (*Config, error) {
	path, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{
				Mode:              "tun",
				SelectedNodeIndex: -1,
			}, nil
		}
		return nil, err
	}

	var cfg Config
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func SaveConfig(cfg *Config) error {
	path, err := GetConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
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
