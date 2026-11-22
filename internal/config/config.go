package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// PortMapping maps a UniFi port index (1-based) to a FreeBSD interface.
// Unmapped ports on the chosen UXG model are reported disabled (enable: false, up: false).
type PortMapping struct {
	PortIdx int    `json:"port_idx"`
	Device  string `json:"device"`            // Physical/FreeBSD interface, e.g. "ixl0", "ixl1", "vtnet0"
	WanIf   string `json:"wan_if,omitempty"`  // Optional logical WAN interface (e.g. "pppoe0") for IP/gw stats
	Role    string `json:"role,omitempty"`    // "wan", "wan2", "lan" (defaults to model role)
	Media   string `json:"media,omitempty"`   // Optional media override ("2.5GbE", "10GbE", "SFP+")
	Label   string `json:"label,omitempty"`   // Optional human note (not sent as port_table.name, which must be ethN)
}

// Config is the static user configuration loaded from disk (e.g. /usr/local/etc/pfsense-unifi-agent.json).
type Config struct {
	InformURL       string        `json:"inform_url"`
	Model           string        `json:"model,omitempty"`            // Default: "UXGA6AA" (UniFi Gateway Fiber)
	Version         string        `json:"version,omitempty"`          // Override reported firmware version
	Hostname        string        `json:"hostname,omitempty"`         // Override OS hostname
	MAC             string        `json:"mac,omitempty"`              // Override device identity MAC (default: primary LAN NIC MAC)
	IP              string        `json:"ip,omitempty"`               // Override management IP (default: primary LAN NIC IP)
	PrimaryLanIf    string        `json:"primary_lan_if,omitempty"`   // Default: first mapped LAN port device (e.g. "ixl1")
	PrimaryWanIf    string        `json:"primary_wan_if,omitempty"`   // Default: first mapped WAN port's wan_if or device (e.g. "pppoe0")
	DpingerGateway  string        `json:"dpinger_gateway,omitempty"`  // Optional dpinger gateway name prefix (e.g. "WAN_PPPOE")
	StateFile       string        `json:"state_file,omitempty"`       // Default: "/var/db/pfsense-unifi-agent/state.json"
	PfSenseConfig   string        `json:"pfsense_config,omitempty"`   // Default: "/cf/conf/config.xml"
	KeaLeasesFile   string        `json:"kea_leases_file,omitempty"`  // Default: "/var/db/kea/dhcp4.leases"
	ISCLeasesFile   string        `json:"isc_leases_file,omitempty"`  // Default: "/var/dhcpd/var/db/dhcpd.leases"
	DpingerSockGlob string        `json:"dpinger_sock_glob,omitempty"`// Default: "/var/run/dpinger_*.sock"
	IntervalSec     int           `json:"interval_sec,omitempty"`     // Default: 10 (overridden by controller noop interval)
	Ports           []PortMapping `json:"ports"`
}

// State persists adoption credentials and cfgversion across restarts.
type State struct {
	Adopted         bool   `json:"adopted"`
	AuthKeyHex      string `json:"authkey_hex,omitempty"`
	UseGCM          bool   `json:"use_gcm"`
	CfgVersion      string `json:"cfgversion,omitempty"`
	ReportedVersion string `json:"reported_version,omitempty"`
	InformURL       string `json:"inform_url,omitempty"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) ApplyDefaults() {
	if c.Model == "" {
		c.Model = "UXGA6AA"
	}
	if c.StateFile == "" {
		c.StateFile = "/var/db/pfsense-unifi-agent/state.json"
	}
	if c.PfSenseConfig == "" {
		c.PfSenseConfig = "/cf/conf/config.xml"
	}
	if c.KeaLeasesFile == "" {
		c.KeaLeasesFile = "/var/db/kea/dhcp4.leases"
	}
	if c.ISCLeasesFile == "" {
		c.ISCLeasesFile = "/var/dhcpd/var/db/dhcpd.leases"
	}
	if c.DpingerSockGlob == "" {
		c.DpingerSockGlob = "/var/run/dpinger_*.sock"
	}
	if c.IntervalSec <= 0 {
		c.IntervalSec = 10
	}
	for i := range c.Ports {
		c.Ports[i].Role = strings.ToLower(strings.TrimSpace(c.Ports[i].Role))
	}
	if c.PrimaryLanIf == "" {
		for _, p := range c.Ports {
			if p.Role == "lan" && p.Device != "" {
				c.PrimaryLanIf = p.Device
				break
			}
		}
	}
	if c.PrimaryWanIf == "" {
		for _, p := range c.Ports {
			if p.Role == "wan" {
				if p.WanIf != "" {
					c.PrimaryWanIf = p.WanIf
				} else if p.Device != "" {
					c.PrimaryWanIf = p.Device
				}
				break
			}
		}
	}
}

func (c *Config) Validate() error {
	if c.InformURL == "" {
		return fmt.Errorf("config: inform_url is required")
	}
	u, err := url.Parse(c.InformURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("config: invalid inform_url %q", c.InformURL)
	}
	seen := make(map[int]bool)
	for _, p := range c.Ports {
		if p.PortIdx <= 0 {
			return fmt.Errorf("config: port_idx must be >= 1")
		}
		if seen[p.PortIdx] {
			return fmt.Errorf("config: duplicate port_idx %d", p.PortIdx)
		}
		seen[p.PortIdx] = true
		if p.Device == "" {
			return fmt.Errorf("config: port_idx %d requires device", p.PortIdx)
		}
	}
	return nil
}

func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &State{CfgVersion: "0"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.CfgVersion == "" {
		s.CfgVersion = "0"
	}
	return &s, nil
}

func SaveState(path string, s *State) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	return os.Rename(tmp, path)
}
