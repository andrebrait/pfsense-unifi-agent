package inform

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/andrebrait/pfsense-unifi-agent/internal/config"
)

// Result summarizes one inform round-trip.
type Result struct {
	HTTPStatus   int
	ReplyType    string
	NextInterval time.Duration
	Immediate    bool
	StateChanged bool
}

// Client manages the UniFi inform transport and adoption/provisioning state machine.
// It is strictly inform-only: controller system_cfg payloads are acknowledged via cfgversion
// without modifying the host router configuration.
type Client struct {
	HTTP       *http.Client
	State      *config.State
	StatePath  string
	InformURL  string
	DefaultInt time.Duration
	Locating   bool
	Logger     *log.Logger
}

func NewClient(informURL string, state *config.State, statePath string, defaultInterval time.Duration, logger *log.Logger) *Client {
	if logger == nil {
		logger = log.Default()
	}
	if defaultInterval <= 0 {
		defaultInterval = 10 * time.Second
	}
	return &Client{
		HTTP:       &http.Client{Timeout: 15 * time.Second},
		State:      state,
		StatePath:  statePath,
		InformURL:  informURL,
		DefaultInt: defaultInterval,
		Logger:     logger,
	}
}

func (c *Client) activeKey() ([]byte, error) {
	if c.State.Adopted && c.State.AuthKeyHex != "" {
		return ParseKey(c.State.AuthKeyHex)
	}
	return ParseKey(FactoryKeyHex)
}

func (c *Client) activeURL() string {
	if c.State.InformURL != "" {
		return c.State.InformURL
	}
	return c.InformURL
}

// Send transmits one inform payload and processes any controller reply.
func (c *Client) Send(macStr string, payload map[string]any) (Result, error) {
	res := Result{NextInterval: c.DefaultInt}

	mac, err := ParseMAC(macStr)
	if err != nil {
		return res, err
	}
	key, err := c.activeKey()
	if err != nil {
		return res, err
	}

	// Ensure transport-controlled fields always match current state.
	payload["mac"] = strings.ToLower(macStr)
	payload["default"] = !c.State.Adopted
	payload["cfgversion"] = c.State.CfgVersion
	payload["inform_url"] = c.activeURL()
	if c.State.Adopted {
		payload["state"] = 2
	} else {
		payload["state"] = 1
	}
	if c.Locating {
		payload["locating"] = true
	}
	if c.State.ReportedVersion != "" {
		payload["version"] = c.State.ReportedVersion
	}

	pkt, err := Encode(mac, key, c.State.UseGCM, payload)
	if err != nil {
		return res, err
	}

	req, err := http.NewRequest(http.MethodPost, c.activeURL(), bytes.NewReader(pkt))
	if err != nil {
		return res, err
	}
	req.Header.Set("Content-Type", "application/x-binary")
	req.Header.Set("User-Agent", "AirControl Agent v1.0")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return res, fmt.Errorf("POST %s: %w", c.activeURL(), err)
	}
	defer resp.Body.Close()

	res.HTTPStatus = resp.StatusCode
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return res, fmt.Errorf("read response: %w", err)
	}

	// HTTP 404 with empty body is normal while pending adoption.
	if resp.StatusCode == http.StatusNotFound && len(body) == 0 {
		return res, nil
	}
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("controller returned HTTP %d (body=%d bytes)", resp.StatusCode, len(body))
	}
	if len(body) == 0 {
		return res, nil
	}

	reply, err := Decode(key, c.State.UseGCM, body)
	if err != nil {
		return res, fmt.Errorf("decode controller reply: %w", err)
	}

	c.applyReply(reply, &res)

	if res.StateChanged && c.StatePath != "" {
		if err := config.SaveState(c.StatePath, c.State); err != nil {
			c.Logger.Printf("WARN: save state failed: %v", err)
		}
	}
	return res, nil
}

func (c *Client) applyReply(reply map[string]any, res *Result) {
	rtype, _ := reply["_type"].(string)
	res.ReplyType = rtype

	switch rtype {
	case "noop":
		if iv, ok := reply["interval"].(float64); ok && iv >= 5 && iv <= 120 {
			res.NextInterval = time.Duration(iv) * time.Second
		}

	case "setparam":
		if mgmt, ok := reply["mgmt_cfg"].(string); ok {
			c.parseMgmtCfg(mgmt, res)
		}
		if cv, ok := reply["cfgversion"].(string); ok && cv != "" && cv != c.State.CfgVersion {
			c.State.CfgVersion = cv
			res.StateChanged = true
		}
		if syscfg, ok := reply["system_cfg"].(string); ok && len(syscfg) > 0 {
			c.Logger.Printf("received system_cfg (%d bytes) for cfgversion=%s (inform-only: acknowledging without applying)", len(syscfg), c.State.CfgVersion)
		}
		res.Immediate = true

	case "cmd":
		cmdName, _ := reply["cmd"].(string)
		switch cmdName {
		case "set-adopt":
			if !c.State.Adopted {
				if k, ok := reply["key"].(string); ok {
					if _, err := ParseKey(k); err == nil {
						c.State.AuthKeyHex = strings.ToLower(strings.TrimSpace(k))
						c.State.Adopted = true
						res.StateChanged = true
						c.Logger.Printf("adopted via cmd set-adopt")
					}
				}
				if uri, ok := reply["uri"].(string); ok && strings.HasPrefix(uri, "http://") {
					c.State.InformURL = uri
					res.StateChanged = true
				}
			} else {
				c.Logger.Printf("ignoring cmd set-adopt while already adopted")
			}
		case "set-locate":
			c.Locating = true
			c.Logger.Printf("locate enabled")
		case "unset-locate":
			c.Locating = false
			c.Logger.Printf("locate disabled")
		default:
			c.Logger.Printf("ignoring controller cmd %q (inform-only)", cmdName)
		}
		res.Immediate = true

	case "upgrade":
		// NEVER download or apply Ubiquiti firmware on pfSense.
		// Record the offered version so the controller stops retrying upgrades.
		if ver, ok := reply["version"].(string); ok && ver != "" {
			c.Logger.Printf("refusing firmware upgrade to %s; reporting offered version to silence prompts", ver)
			if c.State.ReportedVersion != ver {
				c.State.ReportedVersion = ver
				res.StateChanged = true
			}
		} else {
			c.Logger.Printf("refusing firmware upgrade (no version in reply)")
		}
		res.Immediate = true

	case "reboot":
		c.Logger.Printf("ignoring controller reboot request (inform-only safety)")
		res.Immediate = true

	case "setdefault":
		// Authenticated with the adopted authkey (+ GCM if latched); reset agent state only.
		c.Logger.Printf("controller requested setdefault: forgetting controller (pfSense untouched)")
		c.State.Adopted = false
		c.State.AuthKeyHex = ""
		c.State.UseGCM = false
		c.State.CfgVersion = "0"
		c.State.InformURL = ""
		res.StateChanged = true
		res.Immediate = true

	default:
		c.Logger.Printf("unhandled controller reply _type=%q", rtype)
	}
}

func (c *Client) parseMgmtCfg(mgmt string, res *Result) {
	for _, rawLine := range strings.Split(mgmt, "\n") {
		line := strings.TrimSpace(rawLine)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "authkey":
			if !c.State.Adopted {
				if _, err := ParseKey(v); err == nil {
					c.State.AuthKeyHex = strings.ToLower(strings.TrimSpace(v))
					c.State.Adopted = true
					res.StateChanged = true
					c.Logger.Printf("adopted new authkey from mgmt_cfg")
				}
			}
		case "use_aes_gcm":
			if v == "true" && !c.State.UseGCM {
				c.State.UseGCM = true
				res.StateChanged = true
				c.Logger.Printf("latched AES-128-GCM transport")
			}
		case "cfgversion":
			if v != "" && v != c.State.CfgVersion {
				c.State.CfgVersion = v
				res.StateChanged = true
			}
		}
	}
}
