package collector

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/andrebrait/pfsense-unifi-agent/internal/config"
)

// FreeBSDCollector gathers live telemetry from pfSense/FreeBSD using standard system tools.
// Strictly read-only: never writes pfSense config or alters interfaces.
type FreeBSDCollector struct {
	Cfg         *config.Config
	hasPrevCPU  bool
	prevCPUTime [5]uint64
}

func NewFreeBSDCollector(cfg *config.Config) *FreeBSDCollector {
	return &FreeBSDCollector{Cfg: cfg}
}

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func (c *FreeBSDCollector) Collect() (*Snapshot, error) {
	now := time.Now()
	snap := &Snapshot{
		Now:          now,
		Ifaces:       make(map[string]*IfInfo),
		PfInterfaces: make(map[string]PfInterface),
		PfVLANs:      make(map[string]PfVLAN),
	}

	// 1. Base interfaces via ifconfig -a
	if out, err := runCmd(5*time.Second, "ifconfig", "-a"); err == nil {
		ParseIfconfig(out, snap.Ifaces)
	}

	// 2. SFP/SFP+ DOM optical diagnostics on mapped interfaces (only where media is SFP or unknown optical)
	for _, pm := range c.Cfg.Ports {
		if pm.Device == "" {
			continue
		}
		if out, err := runCmd(3*time.Second, "ifconfig", "-vvv", pm.Device); err == nil {
			ParseIfconfig(out, snap.Ifaces)
		}
	}

	// 3. 64-bit interface byte/packet/error/drop counters via netstat -ibn
	if out, err := runCmd(5*time.Second, "netstat", "-ibn"); err == nil {
		for name, cnt := range ParseNetstatIBN(out) {
			if info, ok := snap.Ifaces[name]; ok {
				info.Counters = cnt
			}
		}
	}

	// 4. pfSense config.xml (read-only: interfaces + vlans)
	if data, err := os.ReadFile(c.Cfg.PfSenseConfig); err == nil {
		if ifs, vlans, err := ParsePfSenseConfig(data); err == nil {
			snap.PfInterfaces = ifs
			snap.PfVLANs = vlans
		}
	}

	// 5. ARP (IPv4) and NDP (IPv6) neighbor tables -> learned MACs + IPs per port/VLAN
	if out, err := runCmd(5*time.Second, "arp", "-an"); err == nil {
		snap.ARP = ParseARP(out)
	}
	if out, err := runCmd(5*time.Second, "ndp", "-an"); err == nil {
		snap.NDP = ParseNDP(out)
	}
	if data, err := os.ReadFile("/var/etc/dhcp6c.conf"); err == nil {
		snap.DHCPv6PD = ParseDHCPv6PD(data, snap.Ifaces)
	}

	// 6. LLDP neighbors via lldpcli (optional; gracefully skipped if lldpd isn't installed)
	if out, err := runCmd(3*time.Second, "lldpcli", "-f", "json", "show", "neighbors"); err == nil {
		if neighbors, err := ParseLLDP([]byte(out)); err == nil {
			snap.LLDP = neighbors
		}
	}

	// 7. Kea DHCPv4 leases (active counts + hostnames)
	if data, err := os.ReadFile(c.Cfg.KeaLeasesFile); err == nil {
		snap.Leases = ParseKeaLeases(data, now.Unix())
	}

	// 8. dpinger WAN gateway health sockets
	if matches, err := filepath.Glob(c.Cfg.DpingerSockGlob); err == nil {
		for _, sock := range matches {
			if line, err := readUnixSocket(sock, 500*time.Millisecond); err == nil {
				if dp, ok := ParseDpinger(sock, line); ok {
					snap.Dpinger = append(snap.Dpinger, dp)
				}
			}
		}
	}

	// 9. Default IPv4 route & DNS nameservers
	if out, err := runCmd(3*time.Second, "netstat", "-rn", "-f", "inet"); err == nil {
		snap.DefaultGW = ParseDefaultRoute(out)
	}
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		snap.Nameservers = ParseResolvConf(data)
	}

	// 10. System stats (hostname, kernel, arch, uptime, loadavg, CPU%, memory, optional temp)
	snap.Sys = c.collectSys(now)

	return snap, nil
}

func (c *FreeBSDCollector) collectSys(now time.Time) SysInfo {
	sys := SysInfo{
		Load1:  "0.00",
		Load5:  "0.00",
		Load15: "0.00",
	}
	if h, err := os.Hostname(); err == nil {
		sys.Hostname = h
	}
	if out, err := runCmd(2*time.Second, "uname", "-r"); err == nil {
		sys.KernelVersion = strings.TrimSpace(out)
	}
	if out, err := runCmd(2*time.Second, "uname", "-m"); err == nil {
		sys.Architecture = strings.TrimSpace(out)
	}
	if out, err := runCmd(2*time.Second, "sysctl", "-n", "vm.loadavg"); err == nil {
		sys.Load1, sys.Load5, sys.Load15 = ParseLoadAvg(out)
	}
	if out, err := runCmd(2*time.Second, "sysctl", "-n", "kern.boottime"); err == nil {
		if bt := ParseBoottimeSec(out); bt > 0 && now.Unix() > bt {
			sys.UptimeSec = now.Unix() - bt
		}
	}
	if out, err := runCmd(2*time.Second, "sysctl", "-n", "kern.cp_time"); err == nil {
		if cur, ok := ParseCPUTime(out); ok {
			if c.hasPrevCPU {
				sys.CPUPct = ComputeCPUPct(c.prevCPUTime, cur)
			}
			c.prevCPUTime = cur
			c.hasPrevCPU = true
		}
	}

	// Memory: hw.physmem + FreeBSD VM page counts
	pageSize := sysctlU64("vm.stats.vm.v_page_size")
	pageCount := sysctlU64("vm.stats.vm.v_page_count")
	freeCount := sysctlU64("vm.stats.vm.v_free_count")
	inactiveCount := sysctlU64("vm.stats.vm.v_inactive_count")
	physMem := sysctlU64("hw.physmem")
	if physMem > 0 {
		sys.MemTotal = physMem
	} else if pageSize > 0 && pageCount > 0 {
		sys.MemTotal = pageSize * pageCount
	}
	if pageSize > 0 && pageCount > 0 {
		avail := (freeCount + inactiveCount) * pageSize
		if sys.MemTotal > avail {
			sys.MemUsed = sys.MemTotal - avail
		}
	}

	// Optional CPU / ACPI thermal sensor (VMs typically have none)
	for _, oid := range []string{"dev.cpu.0.temperature", "hw.acpi.thermal.tz0.temperature"} {
		if out, err := runCmd(2*time.Second, "sysctl", "-n", oid); err == nil {
			s := strings.TrimSuffix(strings.TrimSpace(out), "C")
			if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && f > 0 && f < 150 {
				sys.HasTemp = true
				sys.TempC = int(f + 0.5)
				break
			}
		}
	}

	return sys
}

func sysctlU64(oid string) uint64 {
	out, err := runCmd(2*time.Second, "sysctl", "-n", oid)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(out), 10, 64)
	return v
}

func readUnixSocket(path string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	b, err := io.ReadAll(io.LimitReader(conn, 4096))
	return string(b), err
}
