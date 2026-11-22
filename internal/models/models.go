package models

import "fmt"

// PortSpec describes one physical port in a UniFi UXG model's uidb.json layout.
type PortSpec struct {
	PortIdx    int
	IfName     string // e.g. "eth0" .. "eth6" (must match uidb.json for ubiosHostsExtractor)
	Media      string // "GE", "2.5GbE", "10GbE", "SFP+", "SFP28"
	DefaultRole string // "lan" or "wan"
	SpeedCaps  int    // UniFi port_table.speed_caps bitmap
}

// ModelSpec defines a standalone UniFi UXG gateway model supported by UniFi Network 10.x.
type ModelSpec struct {
	Model          string
	ModelDisplay   string
	SysID          string
	DefaultVersion string
	Ports          []PortSpec
}

const (
	// Speed capability bits (from UniFi Network 10.x capability_bits.json)
	Speed10H    = 1
	Speed10F    = 2
	Speed100H   = 4
	Speed100F   = 8
	Speed1000H  = 16
	Speed1000F  = 32
	Speed2500F  = 64
	Speed5000F  = 128
	Speed10000F = 256
	Speed25000F = 512
	SpeedAuto   = 1048576

	Caps1GRJ45   = SpeedAuto | Speed10H | Speed10F | Speed100H | Speed100F | Speed1000F
	Caps25GRJ45  = Caps1GRJ45 | Speed2500F
	Caps10GRJ45  = Caps25GRJ45 | Speed5000F | Speed10000F
	Caps10GSFP   = SpeedAuto | Speed1000F | Speed10000F
	Caps25GSFP28 = Caps10GSFP | Speed25000F
)

var catalog = map[string]ModelSpec{
	// UniFi Gateway Fiber (uidb.json: systemIdHexadecimal a6aa, 7 ports)
	"UXGA6AA": {
		Model:          "UXGA6AA",
		ModelDisplay:   "UXG-Fiber",
		SysID:          "a6aa",
		DefaultVersion: "6.0.17.36539",
		Ports: []PortSpec{
			{PortIdx: 1, IfName: "eth0", Media: "2.5GbE", DefaultRole: "lan", SpeedCaps: Caps25GRJ45},
			{PortIdx: 2, IfName: "eth1", Media: "2.5GbE", DefaultRole: "lan", SpeedCaps: Caps25GRJ45},
			{PortIdx: 3, IfName: "eth2", Media: "2.5GbE", DefaultRole: "lan", SpeedCaps: Caps25GRJ45},
			{PortIdx: 4, IfName: "eth3", Media: "2.5GbE", DefaultRole: "lan", SpeedCaps: Caps25GRJ45},
			{PortIdx: 5, IfName: "eth4", Media: "10GbE", DefaultRole: "wan", SpeedCaps: Caps10GRJ45},
			{PortIdx: 6, IfName: "eth5", Media: "SFP+", DefaultRole: "lan", SpeedCaps: Caps10GSFP},
			{PortIdx: 7, IfName: "eth6", Media: "SFP+", DefaultRole: "wan", SpeedCaps: Caps10GSFP},
		},
	},
	// UniFi Gateway Max (uidb.json: a690, 5x 2.5GbE)
	"UXGB": {
		Model:          "UXGB",
		ModelDisplay:   "UXG-Max",
		SysID:          "a690",
		DefaultVersion: "4.1.13.0",
		Ports: []PortSpec{
			{PortIdx: 1, IfName: "eth0", Media: "2.5GbE", DefaultRole: "lan", SpeedCaps: Caps25GRJ45},
			{PortIdx: 2, IfName: "eth1", Media: "2.5GbE", DefaultRole: "lan", SpeedCaps: Caps25GRJ45},
			{PortIdx: 3, IfName: "eth2", Media: "2.5GbE", DefaultRole: "lan", SpeedCaps: Caps25GRJ45},
			{PortIdx: 4, IfName: "eth3", Media: "2.5GbE", DefaultRole: "lan", SpeedCaps: Caps25GRJ45},
			{PortIdx: 5, IfName: "eth4", Media: "2.5GbE", DefaultRole: "wan", SpeedCaps: Caps25GRJ45},
		},
	},
	// UniFi Gateway Pro (uidb.json: ea19, 2x 1G + 2x 10G SFP+)
	"UXGPRO": {
		Model:          "UXGPRO",
		ModelDisplay:   "UXG-Pro",
		SysID:          "ea19",
		DefaultVersion: "4.1.13.0",
		Ports: []PortSpec{
			{PortIdx: 1, IfName: "eth0", Media: "GE", DefaultRole: "wan", SpeedCaps: Caps1GRJ45},
			{PortIdx: 2, IfName: "eth1", Media: "GE", DefaultRole: "lan", SpeedCaps: Caps1GRJ45},
			{PortIdx: 3, IfName: "eth2", Media: "SFP+", DefaultRole: "wan", SpeedCaps: Caps10GSFP},
			{PortIdx: 4, IfName: "eth3", Media: "SFP+", DefaultRole: "lan", SpeedCaps: Caps10GSFP},
		},
	},
	// UniFi Gateway Enterprise (uidb.json: ea3e, 2x 2.5G + 2x 10G SFP+ + 2x 25G SFP28)
	"UXGENT": {
		Model:          "UXGENT",
		ModelDisplay:   "UXG-Enterprise",
		SysID:          "ea3e",
		DefaultVersion: "4.1.13.0",
		Ports: []PortSpec{
			{PortIdx: 1, IfName: "eth0", Media: "2.5GbE", DefaultRole: "wan", SpeedCaps: Caps25GRJ45},
			{PortIdx: 2, IfName: "eth1", Media: "2.5GbE", DefaultRole: "lan", SpeedCaps: Caps25GRJ45},
			{PortIdx: 3, IfName: "eth2", Media: "SFP+", DefaultRole: "lan", SpeedCaps: Caps10GSFP},
			{PortIdx: 4, IfName: "eth3", Media: "SFP+", DefaultRole: "lan", SpeedCaps: Caps10GSFP},
			{PortIdx: 5, IfName: "eth4", Media: "SFP28", DefaultRole: "wan", SpeedCaps: Caps25GSFP28},
			{PortIdx: 6, IfName: "eth5", Media: "SFP28", DefaultRole: "lan", SpeedCaps: Caps25GSFP28},
		},
	},
	// UniFi Gateway Lite (uidb.json: a677, 2x 1G)
	"UXG": {
		Model:          "UXG",
		ModelDisplay:   "UXG-Lite",
		SysID:          "a677",
		DefaultVersion: "4.1.13.0",
		Ports: []PortSpec{
			{PortIdx: 1, IfName: "eth0", Media: "GE", DefaultRole: "lan", SpeedCaps: Caps1GRJ45},
			{PortIdx: 2, IfName: "eth1", Media: "GE", DefaultRole: "wan", SpeedCaps: Caps1GRJ45},
		},
	},
}

func Lookup(model string) (ModelSpec, error) {
	if model == "" {
		model = "UXGA6AA"
	}
	spec, ok := catalog[model]
	if !ok {
		return ModelSpec{}, fmt.Errorf("unsupported model %q (supported: UXGA6AA, UXGB, UXGPRO, UXGENT, UXG)", model)
	}
	return spec, nil
}
