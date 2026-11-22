package collector

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/andrebrait/pfsense-unifi-agent/internal/config"
	"github.com/andrebrait/pfsense-unifi-agent/internal/models"
)

type SFPInfo struct {
	Found       bool
	Compliance  string
	Vendor      string
	Part        string
	Serial      string
	Temperature string
	Voltage     string
	Current     string
	RxPower     string
	TxPower     string
}

type IfCounters struct {
	RxPackets uint64
	RxErrors  uint64
	RxDropped uint64
	RxBytes   uint64
	TxPackets uint64
	TxErrors  uint64
	TxBytes   uint64
	RxRateBPS uint64 // bits/sec (UniFi xbPjw divides port_table rx_rate by 8 for rx_bytes-r)
	TxRateBPS uint64 // bits/sec
}

type IfInfo struct {
	Name       string
	MAC        string
	Up         bool
	AdminUp    bool
	MTU        int
	Speed      int
	FullDuplex bool
	Autoneg    bool
	IP         string
	Netmask    string
	PeerIP     string   // For PPPoE point-to-point links
	IPv6       []string // CIDR strings with zone stripped, e.g. "2001:db8:1::1/64"
	PeerIPv6   string
	VLANID     int
	VLANParent string
	Counters   IfCounters
	SFP        SFPInfo
}

type ARPEntry struct {
	IP    string
	MAC   string
	Iface string
	Age   int
}

type LLDPNeighbor struct {
	LocalIf    string
	ChassisID  string
	SystemName string
	PortID     string
	PortDescr  string
}

type DHCPLease struct {
	IP       string
	MAC      string
	Hostname string
	Expire   int64
}

type DpingerStat struct {
	Name      string
	SourceIP  string
	TargetIP  string
	LatencyUS int64
	StddevUS  int64
	LossPct   int
}

type PfInterface struct {
	Key     string // e.g. "wan", "lan", "opt2"
	If      string // e.g. "pppoe0", "ixl1", "ixl1.2"
	Descr   string // e.g. "LAN_IoT"
	Enabled bool
}

type PfVLAN struct {
	VLANIf string
	Parent string
	Tag    int
	Descr  string
}

type SysInfo struct {
	Hostname      string
	KernelVersion string
	Architecture  string
	UptimeSec     int64
	Load1         string
	Load5         string
	Load15        string
	CPUPct        float64
	MemTotal      uint64
	MemUsed       uint64
	HasTemp       bool
	TempC         int
}

// Snapshot holds one complete point-in-time telemetry capture from pfSense/FreeBSD.
type Snapshot struct {
	Now          time.Time
	Sys          SysInfo
	Ifaces       map[string]*IfInfo
	ARP          []ARPEntry
	NDP          []ARPEntry
	LLDP         []LLDPNeighbor
	Leases       []DHCPLease
	DHCPv6PD     []string
	Dpinger      []DpingerStat
	DefaultGW    string
	Nameservers  []string
	PfInterfaces map[string]PfInterface // keyed by FreeBSD ifname (e.g. "ixl1.2")
	PfVLANs      map[string]PfVLAN      // keyed by vlanif (e.g. "ixl1.2")
}

// ResolveIdentity determines the gateway's reported MAC and management IP.
func ResolveIdentity(cfg *config.Config, snap *Snapshot) (mac, ip, netmask string) {
	mac = strings.ToLower(strings.TrimSpace(cfg.MAC))
	ip = strings.TrimSpace(cfg.IP)
	netmask = "255.255.255.0"

	if lanIf, ok := snap.Ifaces[cfg.PrimaryLanIf]; ok {
		if mac == "" {
			mac = strings.ToLower(lanIf.MAC)
		}
		if ip == "" {
			ip = lanIf.IP
		}
		if lanIf.Netmask != "" {
			netmask = lanIf.Netmask
		}
	}
	return mac, ip, netmask
}

// BuildPayload converts a FreeBSD/pfSense Snapshot into a UniFi Network 10.x UXG inform JSON map.
func BuildPayload(cfg *config.Config, spec models.ModelSpec, snap *Snapshot) (map[string]any, string, error) {
	mac, ip, netmask := ResolveIdentity(cfg, snap)
	if mac == "" {
		return nil, "", fmt.Errorf("cannot determine gateway MAC (set mac or primary_lan_if in config)")
	}
	if ip == "" {
		return nil, "", fmt.Errorf("cannot determine gateway IP (set ip or primary_lan_if in config)")
	}

	hostname := cfg.Hostname
	if hostname == "" {
		hostname = snap.Sys.Hostname
	}
	if hostname == "" {
		hostname = "pfsense"
	}
	version := cfg.Version
	if version == "" {
		version = spec.DefaultVersion
	}

	// Build port mapping lookup: port_idx -> PortMapping, and physical device -> (port_idx, unifi_ifname)
	portByIdx := make(map[int]config.PortMapping, len(cfg.Ports))
	devToPort := make(map[string]models.PortSpec, len(cfg.Ports))
	for _, pm := range cfg.Ports {
		portByIdx[pm.PortIdx] = pm
	}
	for _, ps := range spec.Ports {
		if pm, ok := portByIdx[ps.PortIdx]; ok {
			devToPort[pm.Device] = ps
		}
	}

	// Lease lookup by MAC (lowercase) and subnet counts
	hostByMAC := make(map[string]string, len(snap.Leases))
	for _, l := range snap.Leases {
		if l.Hostname != "" {
			hostByMAC[strings.ToLower(l.MAC)] = l.Hostname
		}
	}

	// Map each FreeBSD interface (including VLAN subinterfaces) to (physical parent, vid)
	resolveParentVLAN := func(ifname string) (parent string, vid int) {
		if info, ok := snap.Ifaces[ifname]; ok && info.VLANParent != "" {
			return info.VLANParent, info.VLANID
		}
		if v, ok := snap.PfVLANs[ifname]; ok && v.Parent != "" {
			return v.Parent, v.Tag
		}
		return ifname, 1
	}

	// Group ARP (IPv4) and NDP (IPv6) entries by physical port_idx
	macTableByPort := make(map[int][]map[string]any)
	macTableV6ByPort := make(map[int][]map[string]any)
	appendNeighbor := func(dst map[int][]map[string]any, a ARPEntry) {
		parent, vid := resolveParentVLAN(a.Iface)
		ps, ok := devToPort[parent]
		if !ok {
			return
		}
		if pm, hasPM := portByIdx[ps.PortIdx]; hasPM {
			role := pm.Role
			if role == "" {
				role = ps.DefaultRole
			}
			if role == "wan" || role == "wan2" {
				return
			}
		}
		entry := map[string]any{
			"mac":  strings.ToLower(a.MAC),
			"ip":   a.IP,
			"vlan": vid,
			"age":  a.Age,
		}
		if h := hostByMAC[strings.ToLower(a.MAC)]; h != "" {
			entry["hostname"] = h
		}
		dst[ps.PortIdx] = append(dst[ps.PortIdx], entry)
	}
	for _, a := range snap.ARP {
		appendNeighbor(macTableByPort, a)
	}
	for _, a := range snap.NDP {
		appendNeighbor(macTableV6ByPort, a)
	}

	// Group LLDP neighbors by physical port_idx and build top-level lldp_table
	lldpByPort := make(map[int][]map[string]any)
	topLLDP := make([]map[string]any, 0, len(snap.LLDP))
	for _, n := range snap.LLDP {
		ps, ok := devToPort[n.LocalIf]
		if !ok {
			continue
		}
		portID := n.PortID
		if n.PortDescr != "" {
			portID = n.PortDescr
		}
		perPort := map[string]any{
			"lldp_chassis_id":  strings.ToLower(n.ChassisID),
			"lldp_port_id":     portID,
			"lldp_system_name": n.SystemName,
		}
		if n.PortDescr != "" {
			perPort["lldp_port_descr"] = n.PortDescr
		}
		lldpByPort[ps.PortIdx] = append(lldpByPort[ps.PortIdx], perPort)

		top := map[string]any{
			"chassis_id":      strings.ToLower(n.ChassisID),
			"local_port_idx":  ps.PortIdx,
			"local_port_name": ps.IfName,
			"port_id":         portID,
			"system_name":     n.SystemName,
		}
		if n.PortDescr != "" {
			top["port_descr"] = n.PortDescr
		}
		topLLDP = append(topLLDP, top)
	}

	// Build port_table and ethernet_table (every model port must be represented).
	portTable := make([]map[string]any, 0, len(spec.Ports))
	ethTable := make([]map[string]any, 0, len(spec.Ports))
	var primaryWanSpec *models.PortSpec
	var primaryWanMap *config.PortMapping

	for i := range spec.Ports {
		ps := spec.Ports[i]
		pm, mapped := portByIdx[ps.PortIdx]

		portMAC := mac
		if mapped {
			if info, ok := snap.Ifaces[pm.Device]; ok && info.MAC != "" {
				portMAC = strings.ToLower(info.MAC)
			}
		}
		ethTable = append(ethTable, map[string]any{
			"mac":      portMAC,
			"name":     ps.IfName,
			"num_port": 1,
		})

		media := ps.Media
		if mapped && pm.Media != "" {
			media = pm.Media
		}

		// Both "name" and "ifname" MUST equal uidb.json's ethN for UXG ubiosHostsExtractor.
		pe := map[string]any{
			"port_idx":    ps.PortIdx,
			"name":        ps.IfName,
			"ifname":      ps.IfName,
			"media":       media,
			"speed_caps":  ps.SpeedCaps,
			"poe_caps":    0,
			"port_poe":    false,
			"enable":      true,
			"up":          false,
			"speed":       0,
			"full_duplex": false,
			"autoneg":     !strings.HasPrefix(media, "SFP"),
		}

		if mapped {
			role := pm.Role
			if role == "" {
				role = ps.DefaultRole
			}
			if role == "wan" && primaryWanSpec == nil {
				psCopy := ps
				pmCopy := pm
				primaryWanSpec = &psCopy
				primaryWanMap = &pmCopy
			}

			if info, ok := snap.Ifaces[pm.Device]; ok {
				pe["enable"] = info.AdminUp
				pe["up"] = info.Up
				pe["speed"] = info.Speed
				if info.Speed >= 10000 && ps.SpeedCaps&models.Speed10000F == 0 {
					pe["speed_caps"] = ps.SpeedCaps | models.Speed5000F | models.Speed10000F
				}
				pe["full_duplex"] = info.FullDuplex
				pe["autoneg"] = info.Autoneg
				cnt := info.Counters
				if pm.WanIf != "" {
					if wi, wok := snap.Ifaces[pm.WanIf]; wok && (wi.Counters.RxBytes > 0 || wi.Counters.TxBytes > 0) {
						cnt = wi.Counters
					}
				}
				pe["rx_bytes"] = cnt.RxBytes
				pe["tx_bytes"] = cnt.TxBytes
				pe["rx_packets"] = cnt.RxPackets
				pe["tx_packets"] = cnt.TxPackets
				pe["rx_errors"] = cnt.RxErrors
				pe["tx_errors"] = cnt.TxErrors
				pe["rx_dropped"] = cnt.RxDropped
				pe["rx_rate"] = cnt.RxRateBPS
				pe["tx_rate"] = cnt.TxRateBPS

				if info.SFP.Found {
					pe["sfp_found"] = true
					pe["sfp_eeprom"] = true
					pe["sfp_rxfault"] = false
					pe["sfp_txfault"] = false
					if info.SFP.Compliance != "" {
						pe["sfp_compliance"] = info.SFP.Compliance
					}
					if info.SFP.Vendor != "" {
						pe["sfp_vendor"] = info.SFP.Vendor
					}
					if info.SFP.Part != "" {
						pe["sfp_part"] = info.SFP.Part
					}
					if info.SFP.Serial != "" {
						pe["sfp_serial"] = info.SFP.Serial
					}
					if info.SFP.Temperature != "" {
						pe["sfp_temperature"] = info.SFP.Temperature
					}
					if info.SFP.Voltage != "" {
						pe["sfp_voltage"] = info.SFP.Voltage
					}
					if info.SFP.Current != "" {
						pe["sfp_current"] = info.SFP.Current
					}
					if info.SFP.RxPower != "" {
						pe["sfp_rxpower"] = info.SFP.RxPower
					}
					if info.SFP.TxPower != "" {
						pe["sfp_txpower"] = info.SFP.TxPower
					}
				}
			}
			if lldps := lldpByPort[ps.PortIdx]; len(lldps) > 0 {
				pe["lldp_table"] = lldps
			}
			if macs := macTableByPort[ps.PortIdx]; len(macs) > 0 {
				pe["mac_table"] = macs
			}
			if macsV6 := macTableV6ByPort[ps.PortIdx]; len(macsV6) > 0 {
				pe["mac_table_ipv6"] = macsV6
			}
		}

		portTable = append(portTable, pe)
	}

	// Build if_table, network_table, uplink, and config_network_wan/lan.
	ifTable := make([]map[string]any, 0, 8)
	networkTable := make([]map[string]any, 0, 8)

	// Primary WAN (supports PPPoE logical interface over physical SFP+ port, e.g. pppoe0 over ixl0)
	wanUnifiIf := "eth4"
	if primaryWanSpec != nil {
		wanUnifiIf = primaryWanSpec.IfName
	}
	var wanLogical, wanPhysical *IfInfo
	if cfg.PrimaryWanIf != "" {
		wanLogical = snap.Ifaces[cfg.PrimaryWanIf]
	}
	if primaryWanMap != nil {
		wanPhysical = snap.Ifaces[primaryWanMap.Device]
		if wanLogical == nil {
			wanLogical = wanPhysical
		}
	}

	var wanGateways []string
	if wanLogical != nil && wanLogical.PeerIP != "" {
		wanGateways = []string{wanLogical.PeerIP}
	} else if snap.DefaultGW != "" {
		wanGateways = []string{snap.DefaultGW}
	}
	wanDNS := snap.Nameservers
	if len(wanDNS) == 0 {
		wanDNS = []string{}
	}

	var uplink map[string]any
	var configNetWan map[string]any
	if wanLogical != nil {
		wIP := wanLogical.IP
		wMask := wanLogical.Netmask
		if wMask == "" {
			wMask = "255.255.255.255"
		}
		wSpeed := wanLogical.Speed
		wFullDuplex := wanLogical.FullDuplex
		wMAC := strings.ToLower(wanLogical.MAC)
		wCounters := wanLogical.Counters
		if wanPhysical != nil {
			if wSpeed == 0 {
				wSpeed = wanPhysical.Speed
			}
			if !wFullDuplex {
				wFullDuplex = wanPhysical.FullDuplex
			}
			if wMAC == "" {
				wMAC = strings.ToLower(wanPhysical.MAC)
			}
			if wCounters.RxBytes == 0 && wCounters.TxBytes == 0 {
				wCounters = wanPhysical.Counters
			}
		}
		if wMAC == "" {
			wMAC = mac
		}

		wEntry := map[string]any{
			"name":        wanUnifiIf,
			"mac":         wMAC,
			"up":          wanLogical.Up,
			"enable":      wanLogical.AdminUp,
			"speed":       wSpeed,
			"full_duplex": wFullDuplex,
			"ip":          wIP,
			"netmask":     wMask,
			"gateways":    wanGateways,
			"nameservers": wanDNS,
			"rx_bytes":    wCounters.RxBytes,
			"tx_bytes":    wCounters.TxBytes,
			"rx_bytes-r":  wCounters.RxRateBPS / 8,
			"tx_bytes-r":  wCounters.TxRateBPS / 8,
			"rx_rate":     wCounters.RxRateBPS,
			"tx_rate":     wCounters.TxRateBPS,
			"rx_packets":  wCounters.RxPackets,
			"tx_packets":  wCounters.TxPackets,
			"rx_errors":   wCounters.RxErrors,
			"tx_errors":   wCounters.TxErrors,
			"rx_dropped":  wCounters.RxDropped,
			"is_wan":      true,
		}
		ifTable = append(ifTable, wEntry)

		cidr := ipMaskToCIDR(wIP, wMask)
		wanAddrs := make([]string, 0, 1+len(wanLogical.IPv6))
		if cidr != "" {
			wanAddrs = append(wanAddrs, cidr)
		}
		wanAddrs = append(wanAddrs, wanLogical.IPv6...)
		netWan := map[string]any{
			"name":     wanUnifiIf,
			"ip":       wIP,
			"netmask":  wMask,
			"up":       wanLogical.Up,
			"enabled":  wanLogical.AdminUp,
			"mac":      wMAC,
			"rx_bytes": wCounters.RxBytes,
			"tx_bytes": wCounters.TxBytes,
		}
		if cidr != "" {
			netWan["address"] = cidr
		}
		if len(wanAddrs) > 0 {
			netWan["addresses"] = wanAddrs
		}
		if len(snap.DHCPv6PD) > 0 {
			netWan["dhcpv6_pd"] = snap.DHCPv6PD
		}
		networkTable = append(networkTable, netWan)

		uplink = map[string]any{
			"name":        wanUnifiIf,
			"type":        "wire",
			"up":          wanLogical.Up,
			"speed":       wSpeed,
			"full_duplex": wFullDuplex,
			"ip":          wIP,
			"netmask":     wMask,
			"gateways":    wanGateways,
			"nameservers": wanDNS,
			"rx_bytes":    wCounters.RxBytes,
			"tx_bytes":    wCounters.TxBytes,
			"rx_bytes-r":  wCounters.RxRateBPS / 8,
			"tx_bytes-r":  wCounters.TxRateBPS / 8,
			"rx_rate":     wCounters.RxRateBPS,
			"tx_rate":     wCounters.TxRateBPS,
			"rx_packets":  wCounters.RxPackets,
			"tx_packets":  wCounters.TxPackets,
		}
		configNetWan = map[string]any{
			"type":    "dhcp",
			"ip":      wIP,
			"netmask": wMask,
		}
		if len(wanGateways) > 0 {
			configNetWan["gateway"] = wanGateways[0]
		}
		if len(wanDNS) > 0 {
			configNetWan["dns1"] = wanDNS[0]
		}
		if len(wanDNS) > 1 {
			configNetWan["dns2"] = wanDNS[1]
		}
		if len(snap.DHCPv6PD) > 0 || len(wanLogical.IPv6) > 0 {
			configNetWan["type_v6"] = "dhcpv6"
			if wanLogical.PeerIPv6 != "" {
				configNetWan["gateway_v6"] = wanLogical.PeerIPv6
			}
			if len(snap.DHCPv6PD) > 0 {
				if _, n, err := net.ParseCIDR(snap.DHCPv6PD[0]); err == nil {
					ones, _ := n.Mask.Size()
					configNetWan["dhcpv6_pd_size"] = ones
				}
			}
		}
	}

	// Primary LAN (br0) + VLANs on mapped LAN ports (br<VID>) + extra mapped LAN ports
	seenNetName := make(map[string]bool)
	addLanNet := func(brName string, vid int, info *IfInfo) {
		if info == nil || (info.IP == "" && len(info.IPv6) == 0) || seenNetName[brName] {
			return
		}
		seenNetName[brName] = true
		mask := info.Netmask
		if mask == "" {
			mask = "255.255.255.0"
		}
		cidr := ipMaskToCIDR(info.IP, mask)
		addrs := make([]string, 0, 1+len(info.IPv6))
		if cidr != "" {
			addrs = append(addrs, cidr)
		}
		addrs = append(addrs, info.IPv6...)
		leaseCount := countLeasesInSubnet(snap.Leases, cidr)
		ifMAC := strings.ToLower(info.MAC)
		if ifMAC == "" {
			ifMAC = mac
		}

		ifEntry := map[string]any{
			"name":       brName,
			"mac":        ifMAC,
			"up":         info.Up,
			"enable":     info.AdminUp,
			"ip":         info.IP,
			"netmask":    mask,
			"rx_bytes":   info.Counters.RxBytes,
			"tx_bytes":   info.Counters.TxBytes,
			"rx_packets": info.Counters.RxPackets,
			"tx_packets": info.Counters.TxPackets,
		}
		ifTable = append(ifTable, ifEntry)

		netEntry := map[string]any{
			"name":                    brName,
			"ip":                      info.IP,
			"netmask":                 mask,
			"up":                      info.Up,
			"enabled":                 info.AdminUp,
			"mac":                     ifMAC,
			"rx_bytes":                info.Counters.RxBytes,
			"tx_bytes":                info.Counters.TxBytes,
			"active_dhcp_lease_count": leaseCount,
		}
		if cidr != "" {
			netEntry["address"] = cidr
		}
		if len(addrs) > 0 {
			netEntry["addresses"] = addrs
		}
		if vid > 1 {
			netEntry["vlan"] = vid
			netEntry["vlan_enabled"] = true
		}
		networkTable = append(networkTable, netEntry)
	}

	if primaryLan, ok := snap.Ifaces[cfg.PrimaryLanIf]; ok {
		addLanNet("br0", 1, primaryLan)
	}
	for _, info := range snap.Ifaces {
		if info.VLANParent == "" || info.VLANID <= 0 || info.IP == "" {
			continue
		}
		// Include VLANs whose parent is a mapped LAN port
		ps, ok := devToPort[info.VLANParent]
		if !ok {
			continue
		}
		if pm, hasPM := portByIdx[ps.PortIdx]; hasPM {
			role := pm.Role
			if role == "" {
				role = ps.DefaultRole
			}
			if role == "wan" || role == "wan2" {
				continue
			}
		}
		addLanNet(fmt.Sprintf("br%d", info.VLANID), info.VLANID, info)
	}

	// WAN health / uptime_stats from dpinger
	internetUp := wanLogical != nil && wanLogical.Up && wanLogical.IP != ""
	var uptimeStats map[string]any
	if dp := pickPrimaryDpinger(cfg.DpingerGateway, snap.Dpinger); dp != nil {
		avail := float64(100 - dp.LossPct)
		if avail < 0 {
			avail = 0
		}
		latMs := int((dp.LatencyUS + 500) / 1000)
		if dp.LossPct >= 100 {
			internetUp = false
		}
		target := dp.TargetIP
		if target == "" {
			target = dp.Name
		}
		uptimeStats = map[string]any{
			"WAN": map[string]any{
				"availability":    avail,
				"latency_average": latMs,
				"uptime":          snap.Sys.UptimeSec,
				"monitors": []map[string]any{
					{
						"target":          target,
						"type":            "icmp",
						"availability":    avail,
						"latency_average": latMs,
					},
				},
			},
		}
	}

	memPct := 0.0
	if snap.Sys.MemTotal > 0 {
		memPct = float64(snap.Sys.MemUsed) * 100.0 / float64(snap.Sys.MemTotal)
	}

	// Top-level "ip" on a UniFi UXG gateway is the active WAN1 IP (displayed as IP Address (WAN1));
	// IP Address (LAN) is derived from br0 / lan_ip. Fall back to LAN IP when WAN is down or cfg.IP is forced.
	topIP := ip
	topMask := netmask
	if cfg.IP == "" && wanLogical != nil && wanLogical.IP != "" {
		topIP = wanLogical.IP
		if wanLogical.Netmask != "" {
			topMask = wanLogical.Netmask
		} else {
			topMask = "255.255.255.255"
		}
	}

	payload := map[string]any{
		"mac":           mac,
		"serial":        strings.ReplaceAll(mac, ":", ""),
		"ip":            topIP,
		"netmask":       topMask,
		"lan_ip":        ip,
		"hostname":      hostname,
		"model":         spec.Model,
		"model_display": spec.ModelDisplay,
		"sysid":         spec.SysID,
		"version":       version,
		"architecture":  snap.Sys.Architecture,
		"kernel_version": snap.Sys.KernelVersion,
		"uptime":        snap.Sys.UptimeSec,
		"time":          snap.Now.Unix(),
		"internet":      internetUp,
		// Non-empty JSON object is required by UniFi 10.x xbPjw (string is rejected).
		"udapi_version": map[string]any{
			"interfaces":            10,
			"services/lldp":         10,
			"services/dhcp-servers": 10,
		},
		"gw_caps":     0,
		"usg_caps":    2048,         // PORT_REASSIGNMENT: allows reassigning WAN1/WAN2/LAN ports in UniFi UI
		"usg2_caps":   131072 | 128, // ALL_SWITCH_PORTS_REMAP | LINK_LOCAL_IN_NETWORK_TABLE
		"switch_caps": map[string]any{"feature_caps": 0},
		"has_fan":     false,
		"overheating": false,
		"sys_stats": map[string]any{
			"loadavg_1":  snap.Sys.Load1,
			"loadavg_5":  snap.Sys.Load5,
			"loadavg_15": snap.Sys.Load15,
			"mem_total":  snap.Sys.MemTotal,
			"mem_used":   snap.Sys.MemUsed,
			"mem_buffer": 0,
		},
		"system-stats": map[string]any{
			"cpu":    fmt.Sprintf("%.1f", snap.Sys.CPUPct),
			"mem":    fmt.Sprintf("%.1f", memPct),
			"uptime": fmt.Sprintf("%d", snap.Sys.UptimeSec),
		},
		"ethernet_table": ethTable,
		"port_table":     portTable,
		"if_table":       ifTable,
		"network_table":  networkTable,
		"lldp_table":     topLLDP,
	}

	if snap.Sys.HasTemp {
		payload["has_temperature"] = true
		payload["general_temperature"] = snap.Sys.TempC
	} else {
		payload["has_temperature"] = false
	}
	if uplink != nil {
		payload["uplink"] = uplink
	}
	if configNetWan != nil {
		payload["config_network_wan"] = configNetWan
	}
	if lanCIDR := ipMaskToCIDR(ip, netmask); lanCIDR != "" {
		payload["config_network_lan"] = map[string]any{
			"cidr":         lanCIDR,
			"dhcp_enabled": len(snap.Leases) > 0,
		}
	}
	if len(snap.Leases) > 0 {
		activeLeases := make([]map[string]any, 0, len(snap.Leases))
		for _, l := range snap.Leases {
			le := map[string]any{
				"mac": strings.ToLower(l.MAC),
				"ip":  l.IP,
			}
			if l.Hostname != "" {
				le["hostname"] = l.Hostname
			}
			if l.Expire > 0 {
				le["leaseExpiry"] = l.Expire
			}
			activeLeases = append(activeLeases, le)
		}
		payload["ipv4_active_leases"] = activeLeases
	}
	if uptimeStats != nil {
		payload["uptime_stats"] = uptimeStats
	}

	return payload, mac, nil
}

func pickPrimaryDpinger(preferred string, stats []DpingerStat) *DpingerStat {
	if len(stats) == 0 {
		return nil
	}
	if preferred != "" {
		for i := range stats {
			if strings.EqualFold(stats[i].Name, preferred) {
				return &stats[i]
			}
		}
	}
	// Prefer IPv4 dpinger target (avoid IPv6 link-local monitor if an IPv4 WAN monitor exists).
	for i := range stats {
		if stats[i].TargetIP != "" && !strings.Contains(stats[i].TargetIP, ":") {
			return &stats[i]
		}
	}
	return &stats[0]
}

func ipMaskToCIDR(ipStr, maskStr string) string {
	ip := net.ParseIP(ipStr).To4()
	maskIP := net.ParseIP(maskStr).To4()
	if ip == nil || maskIP == nil {
		return ""
	}
	ones, _ := net.IPv4Mask(maskIP[0], maskIP[1], maskIP[2], maskIP[3]).Size()
	return fmt.Sprintf("%s/%d", ip.String(), ones)
}

func countLeasesInSubnet(leases []DHCPLease, cidr string) int {
	if cidr == "" || len(leases) == 0 {
		return 0
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}
	n := 0
	for _, l := range leases {
		if ip := net.ParseIP(l.IP); ip != nil && ipNet.Contains(ip) {
			n++
		}
	}
	return n
}
