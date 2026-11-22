package collector

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	reIfHeader  = regexp.MustCompile(`^([a-zA-Z0-9._-]+):\s+flags=[0-9a-fA-Fx]+<([^>]*)>.*?(?:mtu\s+(\d+))?`)
	reEther     = regexp.MustCompile(`^\s+ether\s+([0-9a-fA-F:]{17})`)
	reInetP2P   = regexp.MustCompile(`^\s+inet\s+(\d+\.\d+\.\d+\.\d+)\s+-->\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)`)
	reInet      = regexp.MustCompile(`^\s+inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)`)
	reInet6P2P  = regexp.MustCompile(`^\s+inet6\s+([0-9a-fA-F:]+)(?:%\S+)?\s+-->\s+([0-9a-fA-F:]+)(?:%\S+)?\s+prefixlen\s+(\d+)`)
	reInet6     = regexp.MustCompile(`^\s+inet6\s+([0-9a-fA-F:]+)(?:%\S+)?\s+prefixlen\s+(\d+)`)
	reVLAN      = regexp.MustCompile(`^\s+vlan:\s+(\d+)\s+.*?parent interface:\s+(\S+)`)
	reMedia     = regexp.MustCompile(`^\s+media:\s+(.+)`)
	reStatus    = regexp.MustCompile(`^\s+status:\s+(.+)`)
	rePlugged   = regexp.MustCompile(`^\s+plugged:\s+(.+)`)
	reVendor    = regexp.MustCompile(`^\s+vendor:\s+(.+?)\s+PN:\s+(.+?)\s+SN:\s+(\S+)`)
	reModTempV  = regexp.MustCompile(`module temperature:\s*([0-9.+-]+)\s*C\s+voltage:\s*([0-9.+-]+)\s*Volts`)
	reRxPower   = regexp.MustCompile(`RX power:\s*[0-9.+-]+\s*mW\s*\(([0-9.+-]+)\s*dBm\)`)
	reTxPower   = regexp.MustCompile(`TX power:\s*[0-9.+-]+\s*mW\s*\(([0-9.+-]+)\s*dBm\)`)
	reTxBias    = regexp.MustCompile(`TX bias:\s*([0-9.+-]+)\s*mA`)
	reARPLine   = regexp.MustCompile(`^\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})\s+on\s+(\S+)\s+(.*)$`)
	reARPExpire = regexp.MustCompile(`expires in\s+(\d+)\s+seconds`)
	reLoadAvg   = regexp.MustCompile(`\{\s*([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s*\}`)
	reBoottime  = regexp.MustCompile(`sec\s*=\s*(\d+)`)
)

// ParseIfconfig parses FreeBSD `ifconfig -a` or `ifconfig -vvv <if>` output.
// If existing is non-nil, parsed fields are merged into it (useful for merging `ifconfig -vvv` DOM data).
func ParseIfconfig(out string, existing map[string]*IfInfo) map[string]*IfInfo {
	if existing == nil {
		existing = make(map[string]*IfInfo)
	}
	var cur *IfInfo
	for _, line := range strings.Split(out, "\n") {
		if m := reIfHeader.FindStringSubmatch(line); m != nil {
			name := m[1]
			info, ok := existing[name]
			if !ok {
				info = &IfInfo{Name: name}
				existing[name] = info
			}
			flags := strings.Split(m[2], ",")
			hasUp, hasRunning := false, false
			for _, f := range flags {
				switch f {
				case "UP":
					hasUp = true
				case "RUNNING":
					hasRunning = true
				}
			}
			info.AdminUp = hasUp
			// Point-to-point/virtual interfaces (e.g. pppoe0) have no "status:" line; UP+RUNNING means up.
			if hasUp && hasRunning {
				info.Up = true
			}
			if m[3] != "" {
				info.MTU, _ = strconv.Atoi(m[3])
			}
			cur = info
			continue
		}
		if cur == nil {
			continue
		}
		if m := reEther.FindStringSubmatch(line); m != nil {
			cur.MAC = strings.ToLower(m[1])
			continue
		}
		if m := reInetP2P.FindStringSubmatch(line); m != nil {
			if cur.IP == "" {
				cur.IP = m[1]
				cur.PeerIP = m[2]
				cur.Netmask = hexMaskToDotted(m[3])
			}
			continue
		}
		if m := reInet.FindStringSubmatch(line); m != nil {
			if cur.IP == "" {
				cur.IP = m[1]
				cur.Netmask = hexMaskToDotted(m[2])
			}
			continue
		}
		if m := reInet6P2P.FindStringSubmatch(line); m != nil {
			cur.IPv6 = appendUnique(cur.IPv6, m[1]+"/"+m[3])
			if cur.PeerIPv6 == "" {
				cur.PeerIPv6 = m[2]
			}
			continue
		}
		if m := reInet6.FindStringSubmatch(line); m != nil {
			if m[1] != "::1" {
				cur.IPv6 = appendUnique(cur.IPv6, m[1]+"/"+m[2])
			}
			continue
		}
		if m := reVLAN.FindStringSubmatch(line); m != nil {
			cur.VLANID, _ = strconv.Atoi(m[1])
			cur.VLANParent = m[2]
			continue
		}
		if m := reMedia.FindStringSubmatch(line); m != nil {
			media := m[1]
			cur.Autoneg = strings.Contains(media, "autoselect")
			cur.FullDuplex = strings.Contains(media, "full-duplex")
			if sp := parseMediaSpeed(media); sp > 0 {
				cur.Speed = sp
			}
			continue
		}
		if m := reStatus.FindStringSubmatch(line); m != nil {
			st := strings.TrimSpace(m[1])
			cur.Up = cur.AdminUp && st == "active"
			if !cur.Up {
				cur.Speed = 0
			}
			continue
		}
		if m := rePlugged.FindStringSubmatch(line); m != nil {
			cur.SFP.Found = true
			cur.SFP.Compliance = strings.TrimSpace(m[1])
			continue
		}
		if m := reVendor.FindStringSubmatch(line); m != nil {
			cur.SFP.Found = true
			cur.SFP.Vendor = strings.TrimSpace(m[1])
			cur.SFP.Part = strings.TrimSpace(m[2])
			cur.SFP.Serial = strings.TrimSpace(m[3])
			continue
		}
		if m := reModTempV.FindStringSubmatch(line); m != nil {
			cur.SFP.Found = true
			cur.SFP.Temperature = m[1]
			cur.SFP.Voltage = m[2]
			continue
		}
		if m := reRxPower.FindStringSubmatch(line); m != nil {
			cur.SFP.Found = true
			cur.SFP.RxPower = m[1]
		}
		if m := reTxPower.FindStringSubmatch(line); m != nil {
			cur.SFP.Found = true
			cur.SFP.TxPower = m[1]
		}
		if m := reTxBias.FindStringSubmatch(line); m != nil {
			cur.SFP.Found = true
			cur.SFP.Current = m[1]
		}
	}
	return existing
}

func hexMaskToDotted(hexStr string) string {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(hexStr), "0x"), 16, 32)
	if err != nil {
		return ""
	}
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
}

func parseMediaSpeed(media string) int {
	// Prefer parenthesized negotiated speed, e.g. "Ethernet autoselect (10Gbase-LR <full-duplex>)"
	s := media
	if idx := strings.Index(s, "("); idx >= 0 {
		s = s[idx+1:]
	}
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "100gbase"):
		return 100000
	case strings.Contains(low, "40gbase"):
		return 40000
	case strings.Contains(low, "25gbase"):
		return 25000
	case strings.Contains(low, "10gbase"):
		return 10000
	case strings.Contains(low, "5000base") || strings.Contains(low, "5gbase"):
		return 5000
	case strings.Contains(low, "2500base") || strings.Contains(low, "2.5gbase"):
		return 2500
	case strings.Contains(low, "1000base"):
		return 1000
	case strings.Contains(low, "100base"):
		return 100
	case strings.Contains(low, "10base"):
		return 10
	default:
		return 0
	}
}

// ParseNetstatIBN parses FreeBSD `netstat -ibn` `<Link#N>` rows into 64-bit interface counters.
func ParseNetstatIBN(out string) map[string]IfCounters {
	res := make(map[string]IfCounters)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		// Expected Link row (12 fields; Address may be missing on pppoe0/lo0 -> 11 fields):
		// Name Mtu <Link#N> [Address] Ipkts Ierrs Idrop Ibytes Opkts Oerrs Obytes Coll
		if len(fields) < 11 || !strings.HasPrefix(fields[2], "<Link#") {
			continue
		}
		name := strings.TrimSuffix(fields[0], "*")
		// Find the 8 numeric columns from the right: Ipkts Ierrs Idrop Ibytes Opkts Oerrs Obytes Coll
		base := len(fields) - 8
		if base < 3 {
			continue
		}
		c := IfCounters{
			RxPackets: parseU64(fields[base]),
			RxErrors:  parseU64(fields[base+1]),
			RxDropped: parseU64(fields[base+2]),
			RxBytes:   parseU64(fields[base+3]),
			TxPackets: parseU64(fields[base+4]),
			TxErrors:  parseU64(fields[base+5]),
			TxBytes:   parseU64(fields[base+6]),
		}
		res[name] = c
	}
	return res
}

func parseU64(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// ParseARP parses FreeBSD `arp -an` output, skipping incomplete and local permanent entries.
func ParseARP(out string) []ARPEntry {
	const defaultMaxAge = 1200
	var entries []ARPEntry
	for _, line := range strings.Split(out, "\n") {
		m := reARPLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		rest := m[4]
		if strings.Contains(rest, "permanent") {
			continue
		}
		age := 0
		if em := reARPExpire.FindStringSubmatch(rest); em != nil {
			if rem, err := strconv.Atoi(em[1]); err == nil && rem <= defaultMaxAge {
				age = defaultMaxAge - rem
			}
		}
		entries = append(entries, ARPEntry{
			IP:    m[1],
			MAC:   strings.ToLower(m[2]),
			Iface: m[3],
			Age:   age,
		})
	}
	return entries
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

// ParseNDP parses FreeBSD `ndp -an` output into neighbor entries for port_table[].mac_table_ipv6.
// Skips permanent local entries, incomplete entries, link-local (fe80::), and multicast (ff00::).
func ParseNDP(out string) []ARPEntry {
	var entries []ARPEntry
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// Format: Neighbor LinklayerAddress Netif Expire S [Flags]
		if len(f) < 5 || f[0] == "Neighbor" {
			continue
		}
		ipStr := f[0]
		if idx := strings.IndexByte(ipStr, '%'); idx >= 0 {
			ipStr = ipStr[:idx]
		}
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() != nil || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsLoopback() {
			continue
		}
		mac := strings.ToLower(f[1])
		if len(mac) != 17 || strings.Count(mac, ":") != 5 {
			continue
		}
		if f[3] == "permanent" {
			continue
		}
		entries = append(entries, ARPEntry{
			IP:    ip.String(),
			MAC:   mac,
			Iface: f[2],
			Age:   0,
		})
	}
	return entries
}

var (
	reDhcp6PrefixIf = regexp.MustCompile(`prefix-interface\s+(\S+)\s*\{`)
	reDhcp6SlaLen   = regexp.MustCompile(`sla-len\s+(\d+)\s*;`)
)

// ParseDHCPv6PD derives delegated IPv6 prefixes from pfSense's /var/etc/dhcp6c.conf sla-len
// and the resulting global IPv6 addresses assigned to those LAN interfaces.
func ParseDHCPv6PD(conf []byte, ifaces map[string]*IfInfo) []string {
	var prefixes []string
	var curIf string
	for _, line := range strings.Split(string(conf), "\n") {
		if m := reDhcp6PrefixIf.FindStringSubmatch(line); m != nil {
			curIf = m[1]
			continue
		}
		if curIf == "" {
			continue
		}
		if strings.Contains(line, "}") {
			curIf = ""
			continue
		}
		if m := reDhcp6SlaLen.FindStringSubmatch(line); m != nil {
			slaLen, err := strconv.Atoi(m[1])
			if err != nil || slaLen <= 0 || slaLen >= 64 {
				continue
			}
			pdLen := 64 - slaLen
			info, ok := ifaces[curIf]
			if !ok {
				continue
			}
			for _, cidr := range info.IPv6 {
				ip, _, err := net.ParseCIDR(cidr)
				if err != nil || ip.To4() != nil || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
					continue
				}
				mask := net.CIDRMask(pdLen, 128)
				pdNet := (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
				prefixes = appendUnique(prefixes, pdNet)
			}
		}
	}
	return prefixes
}

// ParseLLDP parses `lldpcli -f json show neighbors` output.
// Handles both single-object and array encodings used by lldpd depending on neighbor count.
func ParseLLDP(data []byte) ([]LLDPNeighbor, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var root struct {
		LLDP struct {
			Interface json.RawMessage `json:"interface"`
		} `json:"lldp"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if len(root.LLDP.Interface) == 0 {
		return nil, nil
	}

	var rawMaps []map[string]json.RawMessage
	trimmed := bytes.TrimSpace(root.LLDP.Interface)
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &rawMaps); err != nil {
			return nil, err
		}
	} else if trimmed[0] == '{' {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &m); err != nil {
			return nil, err
		}
		rawMaps = []map[string]json.RawMessage{m}
	}

	type lldpChassis struct {
		ID struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"id"`
		Descr string `json:"descr"`
	}
	type lldpEntry struct {
		Chassis map[string]lldpChassis `json:"chassis"`
		Port    struct {
			ID struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"id"`
			Descr string `json:"descr"`
		} `json:"port"`
	}

	var out []LLDPNeighbor
	for _, m := range rawMaps {
		for ifname, raw := range m {
			var e lldpEntry
			if err := json.Unmarshal(raw, &e); err != nil {
				continue
			}
			for sysName, ch := range e.Chassis {
				if ch.ID.Value == "" {
					continue
				}
				out = append(out, LLDPNeighbor{
					LocalIf:    ifname,
					ChassisID:  strings.ToLower(ch.ID.Value),
					SystemName: sysName,
					PortID:     e.Port.ID.Value,
					PortDescr:  e.Port.Descr,
				})
			}
		}
	}
	return out, nil
}

// ParseKeaLeases parses Kea's append-only DHCPv4 CSV lease file (/var/db/kea/dhcp4.leases).
func ParseKeaLeases(data []byte, nowUnix int64) []DHCPLease {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return nil
	}
	col := make(map[string]int, len(header))
	for i, h := range header {
		col[strings.TrimSpace(h)] = i
	}
	idxAddr, okAddr := col["address"]
	idxHW, okHW := col["hwaddr"]
	idxExp, okExp := col["expire"]
	idxState, okState := col["state"]
	idxHost := -1
	if h, ok := col["hostname"]; ok {
		idxHost = h
	}
	if !okAddr || !okHW || !okExp || !okState {
		return nil
	}

	type rawLease struct {
		lease  DHCPLease
		active bool
	}
	latest := make(map[string]rawLease)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) <= idxState || len(rec) <= idxExp || len(rec) <= idxHW || len(rec) <= idxAddr {
			continue
		}
		ip := strings.TrimSpace(rec[idxAddr])
		mac := strings.ToLower(strings.TrimSpace(rec[idxHW]))
		exp, _ := strconv.ParseInt(strings.TrimSpace(rec[idxExp]), 10, 64)
		state, _ := strconv.Atoi(strings.TrimSpace(rec[idxState]))
		host := ""
		if idxHost >= 0 && idxHost < len(rec) {
			host = strings.TrimSpace(rec[idxHost])
		}
		latest[ip] = rawLease{
			lease:  DHCPLease{IP: ip, MAC: mac, Hostname: host},
			active: state == 0 && exp > nowUnix && mac != "",
		}
	}

	out := make([]DHCPLease, 0, len(latest))
	for _, rl := range latest {
		if rl.active {
			out = append(out, rl.lease)
		}
	}
	return out
}

// ParseDpinger parses a dpinger socket response line ("<name> <latency_us> <stddev_us> <loss_pct>")
// along with its socket path ("/var/run/dpinger_<NAME>~<SRC>~<TARGET>.sock").
func ParseDpinger(sockPath, line string) (DpingerStat, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 4 {
		return DpingerStat{}, false
	}
	lat, err1 := strconv.ParseInt(fields[1], 10, 64)
	std, err2 := strconv.ParseInt(fields[2], 10, 64)
	loss, err3 := strconv.Atoi(fields[3])
	if err1 != nil || err2 != nil || err3 != nil {
		return DpingerStat{}, false
	}
	st := DpingerStat{
		Name:      fields[0],
		LatencyUS: lat,
		StddevUS:  std,
		LossPct:   loss,
	}
	base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(sockPath), "dpinger_"), ".sock")
	parts := strings.Split(base, "~")
	if len(parts) >= 3 {
		st.SourceIP = parts[1]
		st.TargetIP = parts[2]
	}
	return st, true
}

// ParsePfSenseConfig reads only <interfaces> and <vlans> from pfSense's /cf/conf/config.xml.
func ParsePfSenseConfig(data []byte) (map[string]PfInterface, map[string]PfVLAN, error) {
	ifaces := make(map[string]PfInterface)
	vlans := make(map[string]PfVLAN)

	dec := xml.NewDecoder(bytes.NewReader(data))
	inInterfaces := false
	inVlans := false
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ifaces, vlans, fmt.Errorf("parse pfSense config.xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && t.Name.Local == "interfaces" {
				inInterfaces = true
				continue
			}
			if depth == 2 && t.Name.Local == "vlans" {
				inVlans = true
				continue
			}
			if inInterfaces && depth == 3 {
				var raw struct {
					If     string    `xml:"if"`
					Descr  string    `xml:"descr"`
					Enable *struct{} `xml:"enable"`
				}
				if err := dec.DecodeElement(&raw, &t); err == nil && raw.If != "" {
					ifaces[raw.If] = PfInterface{
						Key:     t.Name.Local,
						If:      strings.TrimSpace(raw.If),
						Descr:   strings.TrimSpace(raw.Descr),
						Enabled: raw.Enable != nil,
					}
				}
				depth--
				continue
			}
			if inVlans && depth == 3 && t.Name.Local == "vlan" {
				var raw struct {
					If     string `xml:"if"`
					Tag    int    `xml:"tag"`
					Descr  string `xml:"descr"`
					VLANIf string `xml:"vlanif"`
				}
				if err := dec.DecodeElement(&raw, &t); err == nil && raw.VLANIf != "" {
					vlans[raw.VLANIf] = PfVLAN{
						VLANIf: strings.TrimSpace(raw.VLANIf),
						Parent: strings.TrimSpace(raw.If),
						Tag:    raw.Tag,
						Descr:  strings.TrimSpace(raw.Descr),
					}
				}
				depth--
				continue
			}
		case xml.EndElement:
			if depth == 2 && t.Name.Local == "interfaces" {
				inInterfaces = false
			}
			if depth == 2 && t.Name.Local == "vlans" {
				inVlans = false
			}
			depth--
		}
	}
	return ifaces, vlans, nil
}

// ParseDefaultRoute extracts the IPv4 default gateway from FreeBSD `netstat -rn -f inet`.
func ParseDefaultRoute(out string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "default" {
			if net.ParseIP(f[1]) != nil {
				return f[1]
			}
		}
	}
	return ""
}

// ParseResolvConf extracts IPv4 nameservers from /etc/resolv.conf.
func ParseResolvConf(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(f[1]); ip != nil && ip.To4() != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

func ParseLoadAvg(s string) (string, string, string) {
	if m := reLoadAvg.FindStringSubmatch(s); m != nil {
		return m[1], m[2], m[3]
	}
	return "0.00", "0.00", "0.00"
}

func ParseBoottimeSec(s string) int64 {
	if m := reBoottime.FindStringSubmatch(s); m != nil {
		v, _ := strconv.ParseInt(m[1], 10, 64)
		return v
	}
	return 0
}

func ParseCPUTime(s string) ([5]uint64, bool) {
	var out [5]uint64
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) < 5 {
		return out, false
	}
	for i := 0; i < 5; i++ {
		v, err := strconv.ParseUint(f[i], 10, 64)
		if err != nil {
			return out, false
		}
		out[i] = v
	}
	return out, true
}

func ComputeCPUPct(prev, cur [5]uint64) float64 {
	var dTotal uint64
	for i := 0; i < 5; i++ {
		if cur[i] < prev[i] {
			return 0
		}
		dTotal += cur[i] - prev[i]
	}
	if dTotal == 0 {
		return 0
	}
	dIdle := cur[4] - prev[4]
	return float64(dTotal-dIdle) * 100.0 / float64(dTotal)
}
