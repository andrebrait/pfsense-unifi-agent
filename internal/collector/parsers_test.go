package collector

import (
	"testing"
	"time"

	"github.com/andrebrait/pfsense-unifi-agent/internal/config"
	"github.com/andrebrait/pfsense-unifi-agent/internal/models"
)

// Fixtures modeled on pfSense Plus 26.07.1-RELEASE (FreeBSD 16.0-CURRENT) output.
const sampleIfconfig = `ixl0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1508
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
	inet6 fe80::200:ff:fe00:102%ixl1 prefixlen 64 scopeid 0x2
	inet6 2001:db8:abcd:beef:200:ff:fe00:102 prefixlen 64
	media: Ethernet autoselect (10Gbase-Twinax <full-duplex>)
	status: active
	plugged: SFP/SFP+/SFP28 Unknown (Copper pigtail)
	vendor: 10Gtek PN: SFP-H10GB-CU1M SN: SN0000000002 DATE: 2014-05-01
vtnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	ether 02:00:00:00:03:00
	inet 10.255.0.1 netmask 0xffff0000 broadcast 10.255.255.255
	media: Ethernet autoselect (10Gbase-T <full-duplex>)
	status: active
ixl1.2: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	ether 02:00:00:00:01:02
	inet 10.1.0.1 netmask 0xffff0000 broadcast 10.1.255.255
	inet6 2001:db8:abcd:ffff:200:ff:fe00:102 prefixlen 64
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
	inet6 fe80::200:ff:fe00:100%pppoe0 --> fe80::c65e:5cff:fe24:2019%pppoe0 prefixlen 128 scopeid 0x11
`

const sampleNetstat = `Name         Mtu Network                               Address                                            Ipkts       Ierrs       Idrop         Ibytes            Opkts       Oerrs         Obytes        Coll
ixl0        1508 <Link#1>                              02:00:00:00:01:00                        281475935661040           0      487428   830147688460       1458486243           0  1673133762636           0
ixl1        1500 <Link#2>                              02:00:00:00:01:02                             1459833773         253  4294289209  1655606392748        954588581           0   798517238367           0
vtnet0      1500 <Link#3>                              02:00:00:00:03:00                                3537422           0           0     2677226597          3980039           0     1175740975           0
vtnet3*     1500 <Link#6>                              02:00:00:00:03:03                                      0           0           0              0                0           0              0           0
`

const sampleARP = `? (192.168.200.2) at 02:00:00:00:01:00 on ixl0 permanent [ethernet]
? (10.0.0.2) at 02:00:00:00:02:01 on ixl1 expires in 1190 seconds [ethernet]
? (10.1.0.50) at 02:00:00:00:ee:02 on ixl1.2 expires in 1000 seconds [ethernet]
? (10.30.0.10) at 02:00:00:00:ee:30 on ixl1.30 expires in 1150 seconds [ethernet]
? (10.255.0.20) at 02:00:00:00:aa:bb on vtnet0 expires in 600 seconds [ethernet]
`

const sampleLLDP = `{
  "lldp": {
    "interface": {
      "ixl1": {
        "chassis": {
          "switch-core": {
            "id": { "type": "mac", "value": "02:00:00:00:02:01" },
            "descr": "LG510S-4T2XS"
          }
        },
        "port": {
          "id": { "type": "mac", "value": "02:00:00:00:02:01" },
          "descr": "lan6"
        }
      }
    }
  }
}`

const sampleKea = `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.1.1,02:00:00:00:04:01,01:02:00:00:00:04:01,7200,2000000000,1,0,0,nas-box,0,{ "ISC": { "binding-variables": { "domain-name": "home" } } },0
10.0.1.2,02:00:00:00:04:02,,7200,1000,1,0,0,expired-host,0,{ "ISC": { "binding-variables": { "domain-name": "home" } } },0
10.1.0.50,02:00:00:00:ee:02,,7200,2000000000,2,0,0,iot-sensor,0,{ "ISC": { "binding-variables": { "domain-name": "home" } } },0
10.0.1.1,02:00:00:00:04:01,01:02:00:00:00:04:01,7200,2000001000,1,0,0,nas-box-new,0,{ "ISC": { "binding-variables": { "domain-name": "home" } } },0
`

const samplePfXML = `<?xml version="1.0"?>
<pfsense>
  <interfaces>
    <wan><if>pppoe0</if><descr>WAN</descr><enable/></wan>
    <lan><if>ixl1</if><descr>LAN</descr><enable/></lan>
    <opt2><if>ixl1.2</if><descr>LAN_IoT</descr><enable/></opt2>
  </interfaces>
  <vlans>
    <vlan><if>ixl1</if><tag>2</tag><descr>IoT</descr><vlanif>ixl1.2</vlanif></vlan>
  </vlans>
</pfsense>`

func TestParsersAndBuildPayload(t *testing.T) {
	ifaces := ParseIfconfig(sampleIfconfig, nil)
	if ifaces["ixl0"] == nil || ifaces["ixl0"].Speed != 10000 || !ifaces["ixl0"].SFP.Found {
		t.Fatalf("unexpected ixl0: %+v", ifaces["ixl0"])
	}
	if ifaces["ixl0"].SFP.Vendor != "Zaram" || ifaces["ixl0"].SFP.RxPower != "-15.62" || ifaces["ixl0"].SFP.Temperature != "61.50" {
		t.Fatalf("unexpected ixl0 SFP: %+v", ifaces["ixl0"].SFP)
	}
	if ifaces["pppoe0"].IP != "203.0.113.10" || ifaces["pppoe0"].PeerIP != "203.0.113.1" || !ifaces["pppoe0"].Up {
		t.Fatalf("unexpected pppoe0: %+v", ifaces["pppoe0"])
	}
	if ifaces["ixl1.2"].VLANID != 2 || ifaces["ixl1.2"].VLANParent != "ixl1" {
		t.Fatalf("unexpected ixl1.2: %+v", ifaces["ixl1.2"])
	}

	cnts := ParseNetstatIBN(sampleNetstat)
	if cnts["ixl0"].RxBytes != 830147688460 || cnts["ixl1"].TxBytes != 798517238367 {
		t.Fatalf("unexpected counters: %+v", cnts)
	}
	for k, c := range cnts {
		if info, ok := ifaces[k]; ok {
			info.Counters = c
		}
	}

	arps := ParseARP(sampleARP)
	if len(arps) != 4 {
		t.Fatalf("expected 4 dynamic arp entries, got %d: %+v", len(arps), arps)
	}

	const sampleNDP = `Neighbor                             Linklayer Address  Netif Expire    S Flags
fe80::200:ff:fe00:100%ixl0           02:00:00:00:01:00   ixl0 permanent R
2001:db8:abcd:beef::1010             02:00:00:00:02:01   ixl1 12s       R
2001:db8:abcd:ffff::50               02:00:00:00:ee:02 ixl1.2 10m       S
fe80::200:ff:fe00:201%ixl1           02:00:00:00:02:01   ixl1 17h       S
`
	ndps := ParseNDP(sampleNDP)
	if len(ndps) != 2 {
		t.Fatalf("expected 2 global ndp entries, got %d: %+v", len(ndps), ndps)
	}

	const sampleDhcp6c = `
	prefix-interface ixl1 {
		sla-len 16;
	};
`
	pds := ParseDHCPv6PD([]byte(sampleDhcp6c), ifaces)
	if len(pds) != 1 || pds[0] != "2001:db8:abcd::/48" {
		t.Fatalf("expected [2001:db8:abcd::/48], got %v", pds)
	}

	lldps, err := ParseLLDP([]byte(sampleLLDP))
	if err != nil || len(lldps) != 1 || lldps[0].ChassisID != "02:00:00:00:02:01" || lldps[0].PortDescr != "lan6" {
		t.Fatalf("unexpected lldp: %+v err=%v", lldps, err)
	}

	leases := ParseKeaLeases([]byte(sampleKea), 1900000000)
	if len(leases) != 2 {
		t.Fatalf("expected 2 active deduplicated leases, got %d: %+v", len(leases), leases)
	}

	dp, ok := ParseDpinger("/var/run/dpinger_WAN_PPPOE~203.0.113.10~203.0.113.1.sock", "WAN_PPPOE 1113 400 0")
	if !ok || dp.Name != "WAN_PPPOE" || dp.TargetIP != "203.0.113.1" || dp.LatencyUS != 1113 {
		t.Fatalf("unexpected dpinger: %+v ok=%v", dp, ok)
	}

	pfIfs, pfVlans, err := ParsePfSenseConfig([]byte(samplePfXML))
	if err != nil || pfIfs["ixl1.2"].Descr != "LAN_IoT" || pfVlans["ixl1.2"].Tag != 2 {
		t.Fatalf("unexpected pfSense config: %+v %+v err=%v", pfIfs, pfVlans, err)
	}

	cfg := &config.Config{
		InformURL:    "http://10.0.0.4:8080/inform",
		Model:        "UXGA6AA",
		PrimaryLanIf: "ixl1",
		PrimaryWanIf: "pppoe0",
		Ports: []config.PortMapping{
			{PortIdx: 1, Device: "vtnet0", Role: "lan"},
			{PortIdx: 6, Device: "ixl1", Role: "lan"},
			{PortIdx: 7, Device: "ixl0", WanIf: "pppoe0", Role: "wan"},
		},
	}
	cfg.ApplyDefaults()
	spec, _ := models.Lookup(cfg.Model)

	snap := &Snapshot{
		Now:          time.Unix(1900000000, 0),
		Sys:          SysInfo{Hostname: "pfsense.example", KernelVersion: "16.0-CURRENT", Architecture: "amd64", UptimeSec: 10000, Load1: "0.49", Load5: "0.36", Load15: "0.27", CPUPct: 3.2, MemTotal: 6306570240, MemUsed: 2000000000},
		Ifaces:       ifaces,
		ARP:          arps,
		NDP:          ndps,
		LLDP:         lldps,
		Leases:       leases,
		DHCPv6PD:     pds,
		Dpinger:      []DpingerStat{dp},
		DefaultGW:    "203.0.113.1",
		Nameservers:  []string{"1.1.1.1"},
		PfInterfaces: pfIfs,
		PfVLANs:      pfVlans,
	}

	payload, mac, err := BuildPayload(cfg, spec, snap)
	if err != nil {
		t.Fatalf("BuildPayload error: %v", err)
	}
	if mac != "02:00:00:00:01:02" || payload["ip"] != "203.0.113.10" || payload["lan_ip"] != "10.0.0.1" {
		t.Fatalf("unexpected identity mac=%s ip=%v lan_ip=%v", mac, payload["ip"], payload["lan_ip"])
	}
	ports := payload["port_table"].([]map[string]any)
	if len(ports) != 7 {
		t.Fatalf("expected 7 UXGA6AA ports, got %d", len(ports))
	}
	// Port 2 unmapped -> disconnected (up=false, enable=true so UniFi UI does not lock the port)
	if ports[1]["enable"] != true || ports[1]["up"] != false {
		t.Fatalf("expected port 2 disconnected, got %+v", ports[1])
	}
	// Port 6 (ixl1) -> name=eth5, 3 MACs (VLAN 1, 2, 30) + 1 LLDP neighbor
	if ports[5]["name"] != "eth5" || ports[5]["speed"] != 10000 {
		t.Fatalf("unexpected port 6: %+v", ports[5])
	}
	p6Macs := ports[5]["mac_table"].([]map[string]any)
	if len(p6Macs) != 3 {
		t.Fatalf("expected 3 macs on port 6 across VLANs 1/2/30, got %d: %+v", len(p6Macs), p6Macs)
	}
	p6MacsV6 := ports[5]["mac_table_ipv6"].([]map[string]any)
	if len(p6MacsV6) != 2 {
		t.Fatalf("expected 2 IPv6 macs on port 6 across VLANs 1/2, got %d: %+v", len(p6MacsV6), p6MacsV6)
	}
	// Port 7 (ixl0) -> Zaram SFP DOM
	if ports[6]["sfp_vendor"] != "Zaram" || ports[6]["sfp_rxpower"] != "-15.62" {
		t.Fatalf("expected Zaram SFP DOM on port 7, got %+v", ports[6])
	}
}
