# pfsense-unifi-agent

Inform-only UniFi Network gateway agent for pfSense / FreeBSD. Presents a pfSense router to a UniFi Network 10.x controller as a standalone UniFi Gateway (`UXGA6AA` / UniFi Gateway Fiber by default, or `UXGB`, `UXGPRO`, `UXGENT`, `UXG`) without applying controller configuration to pfSense.

## Features

- **Native UniFi `TNBU` inform protocol** with AES-128-CBC initial discovery and latched AES-128-GCM transport (refuses unencrypted replies and CBC downgrades).
- **Strictly inform-only:** acknowledges controller `cfgversion` without touching `/cf/conf/config.xml` or FreeBSD interfaces, refuses Ubiquiti firmware upgrades (reports offered version to silence prompts), ignores `reboot`, and limits `setdefault` to resetting the agent's own state file.
- **Full pfSense / FreeBSD telemetry:**
  - `port_table` + `ethernet_table` (mapped physical ports with link state, negotiated speed/duplex, 64-bit `netstat -ibn` counters, and `ifconfig -vvv` SFP+ optical DOM; unmapped ports reported disabled with `poe_caps: 0`).
  - `port_table[].mac_table` from `arp -an`, mapped to `(physical port, VLAN ID)` via FreeBSD VLAN parent interfaces and enriched with Kea DHCPv4 hostnames.
  - `lldp_table` + `port_table[].lldp_table` from `lldpcli -f json show neighbors` so downstream UniFi/OpenWrt/RTLPlayground switches link underneath pfSense in Topology.
  - `uplink` + `if_table` + `uptime_stats` from WAN/PPPoE interfaces and pfSense `dpinger` sockets (`/var/run/dpinger_*.sock`).
  - `network_table` (`br0`, `br<VID>`) with active Kea DHCPv4 lease counts.
  - `sys_stats` / `system-stats` (CPU%, memory, load averages, uptime, optional thermal sensor).

## Build

Requires Go 1.24+ (zero external dependencies):

```sh
make test
make build-freebsd
```

Output binary: `bin/pfsense-unifi-agent-freebsd-amd64`.

## Install on pfSense

1. Copy the binary and config:

   ```sh
   scp -P 2223 bin/pfsense-unifi-agent-freebsd-amd64 root@firewall:/usr/local/sbin/pfsense-unifi-agent
   scp -P 2223 config.example.json root@firewall:/usr/local/etc/pfsense-unifi-agent.json
   scp -P 2223 rc.d/pfsense_unifi_agent rc.d/pfsense_unifi_agent.sh root@firewall:/usr/local/etc/rc.d/
   ```

2. Edit `/usr/local/etc/pfsense-unifi-agent.json` (`inform_url` must use an IP literal, e.g. `http://10.0.0.200:8080/inform`).
3. Sanity-check collected telemetry before running:

   ```sh
   /usr/local/sbin/pfsense-unifi-agent show
   /usr/local/sbin/pfsense-unifi-agent dump
   ```

4. Enable and start the service (pfSense invokes `/usr/local/etc/rc.d/*.sh` at boot):

   ```sh
   chmod +x /usr/local/sbin/pfsense-unifi-agent /usr/local/etc/rc.d/pfsense_unifi_agent /usr/local/etc/rc.d/pfsense_unifi_agent.sh
   sysrc -f /etc/rc.conf.local pfsense_unifi_agent_enable=YES
   service pfsense_unifi_agent start
   ```

5. In UniFi Network, adopt the pending **UXG Fiber** device. To reset agent state after forgetting the device in the controller:

   ```sh
   /usr/local/sbin/pfsense-unifi-agent forget
   ```

## Notes on VLAN visibility

UniFi Network does not create `Settings -> Networks` entries from gateway informs alone. Mirror your pfSense VLANs (matching VID and subnet) in UniFi `Settings -> Networks` (`purpose: corporate`) to see live per-VLAN `network_table` stats and DHCP lease counts on the gateway while keeping switches provisioned with the same VLANs. Existing Third-Party Gateway (`vlan-only`) networks remain untouched and still classify wired clients reported via `mac_table`.
