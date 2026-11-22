//go:build e2e

package inform_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/andrebrait/pfsense-unifi-agent/internal/collector"
	"github.com/andrebrait/pfsense-unifi-agent/internal/config"
	"github.com/andrebrait/pfsense-unifi-agent/internal/inform"
	"github.com/andrebrait/pfsense-unifi-agent/internal/models"
)

func TestE2EUXGA6AAAdoption(t *testing.T) {
	ctlIP := os.Getenv("UNIFI_E2E_IP")
	if ctlIP == "" {
		t.Skip("set UNIFI_E2E_IP to run e2e adoption test")
	}
	baseAPI := "https://" + ctlIP + ":8443"
	informURL := "http://" + ctlIP + ":8080/inform"

	jar, _ := cookiejar.New(nil)
	api := &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   15 * time.Second,
	}
	apiReq := func(method, path string, body any) map[string]any {
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, baseAPI+path, r)
		req.Header.Set("Content-Type", "application/json")
		resp, err := api.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		if resp.StatusCode != 200 {
			t.Fatalf("%s %s -> HTTP %d: %s", method, path, resp.StatusCode, string(raw))
		}
		return out
	}

	apiReq("POST", "/api/login", map[string]any{"username": "admin", "password": "unifi-containers-seeded"})

	// Create matching VLAN 2 (vlan-only) and VLAN 30 (corporate) networks
	apiReq("POST", "/api/s/default/rest/networkconf", map[string]any{
		"name": "LAN_IoT", "purpose": "vlan-only", "vlan_enabled": true, "vlan": 2,
	})
	apiReq("POST", "/api/s/default/rest/networkconf", map[string]any{
		"name": "LAB_WAN", "purpose": "corporate", "networkgroup": "LAN",
		"vlan_enabled": true, "vlan": 30, "ip_subnet": "10.30.0.1/24",
		"dhcpd_enabled": true, "dhcpd_start": "10.30.0.100", "dhcpd_stop": "10.30.0.200",
	})

	cfg := &config.Config{
		InformURL:      informURL,
		Model:          "UXGA6AA",
		PrimaryLanIf:   "ixl1",
		PrimaryWanIf:   "pppoe0",
		DpingerGateway: "WAN_PPPOE",
		StateFile:      filepath.Join(t.TempDir(), "state.json"),
		IntervalSec:    10,
		Ports: []config.PortMapping{
			{PortIdx: 1, Device: "vtnet0", Role: "lan"},
			{PortIdx: 2, Device: "vtnet1", Role: "lan"},
			{PortIdx: 3, Device: "vtnet2", Role: "lan"},
			{PortIdx: 6, Device: "ixl1", Role: "lan", Media: "SFP+"},
			{PortIdx: 7, Device: "ixl0", WanIf: "pppoe0", Role: "wan", Media: "SFP+"},
		},
	}
	cfg.ApplyDefaults()
	spec, err := models.Lookup(cfg.Model)
	if err != nil {
		t.Fatal(err)
	}

	const ifcfg = `ixl0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1508
	ether 02:00:00:00:01:00
	inet 192.168.200.2 netmask 0xffffff00 broadcast 192.168.200.255
	media: Ethernet autoselect (10Gbase-LR <full-duplex>)
	status: active
	plugged: SFP/SFP+/SFP28 10G Base-LR (SC)
	vendor: Zaram PN: ZXOS11NPI SN: SN0000000001 DATE: 2024-05-12
	module temperature: 61.50 C voltage: 3.37 Volts
	lane 1: RX power: 0.03 mW (-15.62 dBm) TX bias: 19.55 mA
ixl1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	ether 02:00:00:00:01:02
	inet 10.0.0.1 netmask 0xffff0000 broadcast 10.0.255.255
	media: Ethernet autoselect (10Gbase-Twinax <full-duplex>)
	status: active
	plugged: SFP/SFP+/SFP28 Unknown (Copper pigtail)
	vendor: 10Gtek PN: SFP-H10GB-CU1M SN: SN0000000002 DATE: 2014-05-01
vtnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	ether 02:00:00:00:03:00
	inet 10.255.0.1 netmask 0xffff0000 broadcast 10.255.255.255
	media: Ethernet autoselect (10Gbase-T <full-duplex>)
	status: active
vtnet1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	ether 02:00:00:00:03:01
	inet 10.10.0.1 netmask 0xffff0000 broadcast 10.10.255.255
	media: Ethernet autoselect (10Gbase-T <full-duplex>)
	status: active
vtnet2: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	ether 02:00:00:00:03:02
	inet 192.168.57.1 netmask 0xffffff00 broadcast 192.168.57.255
	media: Ethernet autoselect (10Gbase-T <full-duplex>)
	status: active
ixl1.2: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	ether 02:00:00:00:01:02
	inet 10.1.0.1 netmask 0xffff0000 broadcast 10.1.255.255
	vlan: 2 vlanproto: 802.1q vlanpcp: 0 parent interface: ixl1
	media: Ethernet autoselect (10Gbase-Twinax <full-duplex>)
	status: active
ixl1.30: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	ether 02:00:00:00:01:02
	inet 10.30.0.1 netmask 0xffffff00 broadcast 10.30.0.255
	vlan: 30 vlanproto: 802.1q vlanpcp: 0 parent interface: ixl1
	media: Ethernet autoselect (10Gbase-Twinax <full-duplex>)
	status: active
pppoe0: flags=1008851<UP,POINTOPOINT,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	inet 203.0.113.10 --> 203.0.113.1 netmask 0xffffffff
`
	ifaces := collector.ParseIfconfig(ifcfg, nil)
	dp, _ := collector.ParseDpinger("/var/run/dpinger_WAN_PPPOE~203.0.113.10~203.0.113.1.sock", "WAN_PPPOE 1113 400 0")
	snap := &collector.Snapshot{
		Now: time.Now(),
		Sys: collector.SysInfo{
			Hostname: "pfsense.example", KernelVersion: "16.0-CURRENT", Architecture: "amd64",
			UptimeSec: 36000, Load1: "0.49", Load5: "0.36", Load15: "0.27",
			CPUPct: 2.5, MemTotal: 6306570240, MemUsed: 2000000000,
		},
		Ifaces: ifaces,
		ARP: []collector.ARPEntry{
			{IP: "10.0.0.2", MAC: "02:00:00:00:02:01", Iface: "ixl1", Age: 10},
			{IP: "10.1.0.50", MAC: "02:00:00:00:ee:02", Iface: "ixl1.2", Age: 20},
			{IP: "10.30.0.50", MAC: "02:00:00:00:ee:30", Iface: "ixl1.30", Age: 15},
			{IP: "10.255.0.20", MAC: "02:00:00:00:aa:bb", Iface: "vtnet0", Age: 30},
		},
		LLDP: []collector.LLDPNeighbor{
			{LocalIf: "ixl1", ChassisID: "02:00:00:00:02:01", SystemName: "switch-core", PortID: "02:00:00:00:02:01", PortDescr: "lan6"},
		},
		Leases: []collector.DHCPLease{
			{IP: "10.30.0.50", MAC: "02:00:00:00:ee:30", Hostname: "lab-host"},
		},
		Dpinger:     []collector.DpingerStat{dp},
		DefaultGW:   "203.0.113.1",
		Nameservers: []string{"1.1.1.1"},
	}

	st := &config.State{CfgVersion: "0"}
	cli := inform.NewClient(informURL, st, cfg.StateFile, 10*time.Second, log.New(os.Stdout, "e2e: ", 0))

	// 1. Discovery inform (HTTP 404 pending)
	p, mac, err := collector.BuildPayload(cfg, spec, snap)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cli.Send(mac, p)
	if err != nil || res.HTTPStatus != 404 {
		t.Fatalf("discovery inform: res=%+v err=%v", res, err)
	}
	time.Sleep(1500 * time.Millisecond)

	// 2. Adopt via controller API
	apiReq("POST", "/api/s/default/cmd/devmgr", map[string]any{"cmd": "adopt", "mac": mac})

	// 3. Drive inform loop until three consecutive noops (5->1 settle + mac_table ingest in state=1)
	noops := 0
	for i := 0; i < 10; i++ {
		time.Sleep(1500 * time.Millisecond)
		snap.Now = time.Now()
		snap.Sys.UptimeSec += 2
		p, mac, _ = collector.BuildPayload(cfg, spec, snap)
		res, err = cli.Send(mac, p)
		if err != nil {
			t.Fatalf("inform %d: %v", i, err)
		}
		t.Logf("step=%d http=%d reply=%s adopted=%v gcm=%v cfgver=%s", i, res.HTTPStatus, res.ReplyType, st.Adopted, st.UseGCM, st.CfgVersion)
		if res.ReplyType == "noop" {
			noops++
			if noops >= 3 {
				break
			}
		} else {
			noops = 0
		}
	}

	// 4. Verify stat/device and stat/sta
	stat := apiReq("GET", "/api/s/default/stat/device", nil)
	devs := stat["data"].([]any)
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	dev := devs[0].(map[string]any)
	if dev["state"] != float64(1) {
		t.Fatalf("expected state=1 (Connected), got %v", dev["state"])
	}
	if dev["upgradable"] != false {
		t.Fatalf("expected upgradable=false, got %v", dev["upgradable"])
	}
	pt := dev["port_table"].([]any)
	if len(pt) != 7 {
		t.Fatalf("expected 7 ports, got %d", len(pt))
	}
	p4 := pt[3].(map[string]any)
	p5 := pt[4].(map[string]any)
	p6 := pt[5].(map[string]any)
	p7 := pt[6].(map[string]any)
	if p4["up"] != false || p5["up"] != false {
		t.Fatalf("expected ports 4 & 5 down, got p4=%v p5=%v", p4["up"], p5["up"])
	}
	if p6["speed"] != float64(10000) || p6["sfp_vendor"] != "10Gtek" {
		t.Fatalf("unexpected port 6 (ixl1): %v", p6)
	}
	if p7["speed"] != float64(10000) || p7["sfp_vendor"] != "Zaram" || p7["sfp_rxpower"] != "-15.62" {
		t.Fatalf("unexpected port 7 (ixl0): %v", p7)
	}

	sta := apiReq("GET", "/api/s/default/stat/sta", nil)
	clients := sta["data"].([]any)
	t.Logf("UXGA6AA state=%v ports=%d networks=%d clients=%d", dev["state"], len(pt), len(dev["network_table"].([]any)), len(clients))
	if len(clients) < 3 {
		t.Fatalf("expected >=3 wired clients in stat/sta, got %d: %v", len(clients), clients)
	}
}
