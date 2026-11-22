package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/andrebrait/pfsense-unifi-agent/internal/collector"
	"github.com/andrebrait/pfsense-unifi-agent/internal/config"
	"github.com/andrebrait/pfsense-unifi-agent/internal/inform"
	"github.com/andrebrait/pfsense-unifi-agent/internal/models"
)

const defaultConfigPath = "/usr/local/etc/pfsense-unifi-agent.json"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath, "path to JSON config file")
	_ = fs.Parse(os.Args[2:])

	switch cmd {
	case "run":
		if err := cmdRun(*cfgPath); err != nil {
			log.Fatalf("error: %v", err)
		}
	case "show":
		if err := cmdShow(*cfgPath); err != nil {
			log.Fatalf("error: %v", err)
		}
	case "dump":
		if err := cmdDump(*cfgPath); err != nil {
			log.Fatalf("error: %v", err)
		}
	case "forget":
		if err := cmdForget(*cfgPath); err != nil {
			log.Fatalf("error: %v", err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <run|show|dump|forget> [-config %s]\n", os.Args[0], defaultConfigPath)
}

func cmdShow(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	spec, err := models.Lookup(cfg.Model)
	if err != nil {
		return err
	}
	st, err := config.LoadState(cfg.StateFile)
	if err != nil {
		return err
	}
	col := collector.NewFreeBSDCollector(cfg)
	snap, err := col.Collect()
	if err != nil {
		return err
	}
	mac, ip, _ := collector.ResolveIdentity(cfg, snap)

	adoptStr := "pending"
	if st.Adopted {
		adoptStr = fmt.Sprintf("adopted (gcm=%v cfgversion=%s)", st.UseGCM, st.CfgVersion)
	}
	fmt.Printf("%s (%s), gateway — inform-only\n", spec.ModelDisplay, spec.Model)
	fmt.Printf("controller: %s   state: %s\n", cfg.InformURL, adoptStr)
	fmt.Printf("identity:   mac=%s   ip=%s   hostname=%s\n\n", mac, ip, snap.Sys.Hostname)

	portByIdx := make(map[int]config.PortMapping)
	for _, pm := range cfg.Ports {
		portByIdx[pm.PortIdx] = pm
	}
	fmt.Printf("%-5s %-6s %-7s %-10s %-8s %-8s %s\n", "Port", "UniFi", "Media", "FreeBSD", "Role", "Link", "Details")
	for _, ps := range spec.Ports {
		pm, ok := portByIdx[ps.PortIdx]
		if !ok {
			fmt.Printf("%-5d %-6s %-7s %-10s %-8s %-8s %s\n", ps.PortIdx, ps.IfName, ps.Media, "-", "-", "disabled", "(unmapped)")
			continue
		}
		role := pm.Role
		if role == "" {
			role = ps.DefaultRole
		}
		link := "missing"
		detail := ""
		if info, exists := snap.Ifaces[pm.Device]; exists {
			if info.Up {
				link = fmt.Sprintf("%dM", info.Speed)
			} else if info.AdminUp {
				link = "down"
			} else {
				link = "disabled"
			}
			if info.IP != "" {
				detail = info.IP
			}
			if pm.WanIf != "" {
				if wi, wok := snap.Ifaces[pm.WanIf]; wok && wi.IP != "" {
					detail = fmt.Sprintf("%s=%s", pm.WanIf, wi.IP)
				}
			}
			if info.SFP.Found {
				sfpDesc := fmt.Sprintf("%s %s", info.SFP.Vendor, info.SFP.Part)
				if info.SFP.Temperature != "" {
					sfpDesc += " " + info.SFP.Temperature + "C"
				}
				if info.SFP.RxPower != "" {
					sfpDesc += " " + info.SFP.RxPower + "dBm"
				}
				detail = fmt.Sprintf("%s [SFP: %s]", detail, sfpDesc)
			}
		}
		fmt.Printf("%-5d %-6s %-7s %-10s %-8s %-8s %s\n", ps.PortIdx, ps.IfName, ps.Media, pm.Device, role, link, detail)
	}

	fmt.Printf("\nARP entries: %d   LLDP neighbors: %d   Active DHCP leases: %d   dpinger: %d\n",
		len(snap.ARP), len(snap.LLDP), len(snap.Leases), len(snap.Dpinger))
	for _, n := range snap.LLDP {
		fmt.Printf("  LLDP %s -> %s (%s port %s)\n", n.LocalIf, n.SystemName, n.ChassisID, n.PortDescr)
	}
	for _, dp := range snap.Dpinger {
		fmt.Printf("  dpinger %s (%s): %.2f ms, loss %d%%\n", dp.Name, dp.TargetIP, float64(dp.LatencyUS)/1000.0, dp.LossPct)
	}
	return nil
}

func cmdDump(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	spec, err := models.Lookup(cfg.Model)
	if err != nil {
		return err
	}
	col := collector.NewFreeBSDCollector(cfg)
	snap, err := col.Collect()
	if err != nil {
		return err
	}
	payload, _, err := collector.BuildPayload(cfg, spec, snap)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func cmdForget(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	st := &config.State{CfgVersion: "0"}
	if err := config.SaveState(cfg.StateFile, st); err != nil {
		return err
	}
	fmt.Printf("Reset agent adoption state at %s (pfSense configuration untouched).\n", cfg.StateFile)
	return nil
}

func cmdRun(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	spec, err := models.Lookup(cfg.Model)
	if err != nil {
		return err
	}
	st, err := config.LoadState(cfg.StateFile)
	if err != nil {
		return err
	}

	logger := log.New(os.Stderr, "pfsense-unifi-agent: ", log.LstdFlags)
	col := collector.NewFreeBSDCollector(cfg)
	cli := inform.NewClient(cfg.InformURL, st, cfg.StateFile, time.Duration(cfg.IntervalSec)*time.Second, logger)

	// Warm up CPU delta baseline once before entering the inform loop.
	_, _ = col.Collect()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	logger.Printf("starting model=%s inform_url=%s adopted=%v gcm=%v", spec.Model, cfg.InformURL, st.Adopted, st.UseGCM)

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case sig := <-sigCh:
			logger.Printf("received %s, exiting", sig)
			return nil
		case <-timer.C:
			next := time.Duration(cfg.IntervalSec) * time.Second
			snap, err := col.Collect()
			if err != nil {
				logger.Printf("collect error: %v", err)
			} else if payload, mac, err := collector.BuildPayload(cfg, spec, snap); err != nil {
				logger.Printf("build payload error: %v", err)
			} else {
				res, err := cli.Send(mac, payload)
				if err != nil {
					logger.Printf("inform error: %v", err)
				} else {
					if res.ReplyType != "" && res.ReplyType != "noop" {
						logger.Printf("inform HTTP %d reply=%s adopted=%v cfgversion=%s", res.HTTPStatus, res.ReplyType, st.Adopted, st.CfgVersion)
					} else if res.HTTPStatus == 404 {
						logger.Printf("inform HTTP 404 (pending adoption in controller)")
					}
					if res.Immediate {
						next = 1 * time.Second
					} else if res.NextInterval > 0 {
						next = res.NextInterval
					}
				}
			}
			timer.Reset(next)
		}
	}
}
