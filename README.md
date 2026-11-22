# pfsense-unifi-agent

An inform-only agent that lets a UniFi Network controller adopt a pfSense router as a UniFi gateway.

The agent runs on pfSense, speaks the UniFi inform protocol, and presents the router as a standalone UniFi Gateway (by default a UniFi Gateway Fiber, `UXGA6AA`). Once adopted, the controller shows pfSense like any other UniFi gateway: ports with link state, speed and live traffic, WAN status and latency, CPU and memory, DHCP leases, IPv6 addresses and prefix delegation, the clients and switches behind each port, and LLDP neighbors.

**pfSense stays in charge.** The agent reports telemetry and never applies anything the controller sends. Firewall rules, interfaces, DHCP and VPN settings stay in pfSense, and changes made in UniFi only update the controller's database.

## How it works

- **Inform protocol:** speaks UniFi's `TNBU` inform protocol. It starts with AES-128-CBC for discovery and switches to AES-128-GCM after adoption, refusing unencrypted replies and CBC downgrades once GCM is in use.
- **Configuration is acknowledged, not applied:** the agent acknowledges each controller `cfgversion` so the device shows as provisioned, but never touches `/cf/conf/config.xml` or any FreeBSD interface.
- **Firmware upgrades are refused:** the agent reports the offered version afterwards so the controller stops prompting. `reboot`, `speed-test` and similar commands are ignored, and `setdefault` only resets the agent's own state file.
- **Telemetry comes from base FreeBSD tools:** `ifconfig`, `netstat`, `arp`, `ndp` and `sysctl`, plus pfSense's `dpinger` sockets, Kea lease files, and `lldpcli` when it is installed.

## What the controller sees

| Controller feature | Source on pfSense |
| --- | --- |
| Ports: link, speed, duplex, byte and packet counters, live rates | `ifconfig`, `netstat -ibn` |
| SFP+ module details and optical power (DOM) | `ifconfig -vvv` |
| WAN IP, gateway, latency and packet loss | WAN or PPPoE interface, `dpinger` sockets |
| Wired clients per port and VLAN, with hostnames | `arp -an`, `ndp -an`, Kea DHCPv4 leases |
| Networks with active DHCP lease counts | Interface addresses, Kea DHCPv4 leases |
| IPv6 addresses and delegated prefixes | `ifconfig`, the DHCPv6 client |
| LLDP neighbors per port | `lldpcli` (optional) |
| CPU, memory, load and uptime; temperature when a sensor exists | `sysctl` |

## Requirements

- pfSense on amd64. Developed and tested on pfSense Plus 26.07. Recent pfSense CE releases should work, but have not been tested.
- A UniFi Network 10.x controller (a self-hosted Network application or UniFi OS Server) that pfSense can reach on the inform port (TCP 8080 by default).
- Kea as the DHCPv4 server, for lease counts and client hostnames. With ISC DHCP the agent still works but reports no leases.
- Optional: the **lldpd** package (**System → Package Manager**), enabled on your LAN interfaces, so each port lists its LLDP neighbors. Topology does not need it: the controller places devices from the MAC addresses each port reports and the uplinks your UniFi devices report.
- Go 1.24 or newer to build. The agent has no dependencies outside the Go standard library.

## Supported gateway models

Pick a model whose ports can hold your pfSense interfaces. A model port with no pfSense interface mapped to it shows as disabled.

| `model` | Controller name | Ports (index: media, default role) |
| --- | --- | --- |
| `UXGA6AA` (default) | UniFi Gateway Fiber | 1–4: 2.5GbE LAN · 5: 10GbE WAN · 6: SFP+ LAN · 7: SFP+ WAN |
| `UXGB` | UniFi Gateway Max | 1–4: 2.5GbE LAN · 5: 2.5GbE WAN |
| `UXGPRO` | UniFi Gateway Pro | 1: GbE WAN · 2: GbE LAN · 3: SFP+ WAN · 4: SFP+ LAN |
| `UXGENT` | UniFi Gateway Enterprise | 1: 2.5GbE WAN · 2: 2.5GbE LAN · 3–4: SFP+ LAN · 5: SFP28 WAN · 6: SFP28 LAN |
| `UXG` | UniFi Gateway Lite | 1: GbE LAN · 2: GbE WAN |

## Build

```sh
make test
make build-freebsd
```

This produces `bin/pfsense-unifi-agent-freebsd-amd64`, a static binary you can build on any OS.

## Install on pfSense

The steps below use `root@pfsense` for the router; replace it with your own SSH target, and add `-P <port>` to `scp` (`-p <port>` to `ssh`) if SSH does not listen on port 22. SSH must be enabled under **System → Advanced → Admin Access**.

1. **Copy the files:**

   ```sh
   scp bin/pfsense-unifi-agent-freebsd-amd64 root@pfsense:/usr/local/sbin/pfsense-unifi-agent
   scp config.example.json root@pfsense:/usr/local/etc/pfsense-unifi-agent.json
   scp rc.d/pfsense_unifi_agent rc.d/pfsense_unifi_agent.sh root@pfsense:/usr/local/etc/rc.d/
   ssh root@pfsense 'chmod 0755 /usr/local/sbin/pfsense-unifi-agent /usr/local/etc/rc.d/pfsense_unifi_agent /usr/local/etc/rc.d/pfsense_unifi_agent.sh'
   ```

2. **Edit `/usr/local/etc/pfsense-unifi-agent.json`** (see [Configuration](#configuration)):
   - Set `inform_url` to your controller's inform address, using its IP address, for example `http://192.168.1.10:8080/inform`.
   - Map each pfSense interface you want to show to a port of the chosen model. `ifconfig -l` lists the interface names.

3. **Check what the agent collects** before connecting it to the controller:

   ```sh
   /usr/local/sbin/pfsense-unifi-agent show   # port mapping, link state and counts, as a table
   /usr/local/sbin/pfsense-unifi-agent dump   # the full inform payload, as JSON
   ```

   Every mapped port should show a link state rather than `missing`, and the WAN port should show its public IP.

4. **Enable and start the service:**

   ```sh
   sysrc -f /etc/rc.conf.local pfsense_unifi_agent_enable=YES
   service pfsense_unifi_agent start
   ```

   pfSense runs `/usr/local/etc/rc.d/*.sh` at boot, so the `.sh` wrapper starts the agent after a reboot. The agent logs to the system log under `pfsense_unifi_agent`, which you can read under **Status → System Logs** or with `grep pfsense_unifi_agent /var/log/system.log`.

5. **Adopt the gateway:** in UniFi Network, open **UniFi Devices**. The router appears as a pending gateway of the chosen model; click **Adopt**. Within a minute it should show as online with live statistics.

## Configuration

The configuration file is JSON. Only `inform_url` and `ports` are required.

| Key | Default | Meaning |
| --- | --- | --- |
| `inform_url` | (required) | Controller inform URL, such as `http://192.168.1.10:8080/inform`. |
| `model` | `UXGA6AA` | Gateway model to present; see [Supported gateway models](#supported-gateway-models). |
| `ports` | (required) | Maps model ports to pfSense interfaces; see below. |
| `dpinger_gateway` | first gateway found | Name of the pfSense gateway whose `dpinger` latency and loss are reported for WAN1, such as `WAN_PPPOE` or `WAN_DHCP`. |
| `primary_lan_if` | first LAN port's `device` | Interface whose MAC address and IP identify the device to the controller. |
| `primary_wan_if` | first WAN port's `wan_if` or `device` | Interface whose address is reported as the WAN IP. |
| `hostname` | system hostname | Name reported to the controller. |
| `mac`, `ip` | from `primary_lan_if` | Override the device identity. Changing the MAC after adoption makes it a different device. |
| `version` | model's default | Firmware version to report. |
| `interval_sec` | `10` | Seconds between informs, until the controller sets its own interval. |
| `state_file` | `/var/db/pfsense-unifi-agent/state.json` | Where the agent keeps its adoption key. |
| `pfsense_config` | `/cf/conf/config.xml` | Read-only, for interface and VLAN descriptions. |
| `kea_leases_file` | `/var/db/kea/dhcp4.leases` | Kea DHCPv4 lease file. The agent also reads the files Kea's lease cleanup leaves beside it. |
| `dpinger_sock_glob` | `/var/run/dpinger_*.sock` | Where to find `dpinger` sockets. |

Each entry in `ports` takes:

| Key | Meaning |
| --- | --- |
| `port_idx` | Port number on the chosen model, starting at 1. |
| `device` | The physical FreeBSD interface, such as `igc0`, `ix1` or `vtnet0`. Link state, speed and SFP details come from it. |
| `role` | `lan`, `wan` or `wan2`. Defaults to the model port's role. |
| `wan_if` | For a WAN port, the logical interface carrying the WAN address, such as `pppoe0`. Its address and counters are reported for the port. |
| `media` | Overrides the media shown for the port, such as `SFP+` or `10GbE`. |
| `label` | A note for yourself. The controller always names ports after the model. |

VLAN interfaces (`ix1.20`) do not need entries: the agent attributes VLAN traffic and clients to their parent port.

## Networks and VLANs

The controller does not create networks from what a gateway reports. To see per-VLAN statistics and lease counts, create matching networks in UniFi under **Settings → Networks**, with the same VLAN ID and subnet as in pfSense. The agent never applies these settings to pfSense, so turning DHCP or other options on or off there changes nothing on the router.

The same goes for IPv6: to use prefix delegation on a UniFi network, set the delegated prefix size on the WAN under **Settings → Internet** to match what your ISP gives pfSense.

## Commands

| Command | Purpose |
| --- | --- |
| `pfsense-unifi-agent run` | Run the agent (what the service does). |
| `pfsense-unifi-agent show` | Print the port mapping and collected status as a table. |
| `pfsense-unifi-agent dump` | Print the inform payload the agent would send, as JSON. |
| `pfsense-unifi-agent forget` | Clear the adoption state, after removing the device from the controller. |

Each command accepts `-config <path>`; the default is `/usr/local/etc/pfsense-unifi-agent.json`.

## Updating, re-adopting and removing

- **Update:** copy the new binary to `/usr/local/sbin/pfsense-unifi-agent` and run `service pfsense_unifi_agent restart`. The adoption state is kept.
- **Re-adopt:** remove the device in UniFi, then run `service pfsense_unifi_agent stop`, `pfsense-unifi-agent forget` and `service pfsense_unifi_agent start`. The router appears as pending again.
- **Remove:** stop the service, run `sysrc -f /etc/rc.conf.local -x pfsense_unifi_agent_enable`, then delete `/usr/local/sbin/pfsense-unifi-agent`, `/usr/local/etc/pfsense-unifi-agent.json`, the two `rc.d` scripts and `/var/db/pfsense-unifi-agent`.

## Development

`make test` runs the unit tests. An end-to-end adoption test runs against a disposable UniFi Network container:

```sh
UNIFI_E2E_IP=<controller IP> go test -tags e2e ./internal/inform/
```

## License

[GNU Affero General Public License v3.0](LICENSE).

UniFi is a trademark of Ubiquiti Inc., and pfSense is a trademark of Rubicon Communications, LLC (Netgate). This project is not affiliated with or endorsed by either.
