package inform

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/andrebrait/pfsense-unifi-agent/internal/config"
)

func TestClientAdoptionAndSafety(t *testing.T) {
	const newKeyHex = "0123456789abcdef0123456789abcdef"
	factoryKey, _ := ParseKey(FactoryKeyHex)
	adoptedKey, _ := ParseKey(newKeyHex)
	macStr := "02:00:00:00:01:02"
	mac, _ := ParseMAC(macStr)

	step := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		step++
		switch step {
		case 1:
			// Pending 404
			if _, err := Decode(factoryKey, false, body); err != nil {
				t.Errorf("step 1 decode: %v", err)
			}
			w.WriteHeader(http.StatusNotFound)
		case 2:
			// Deliver mgmt_cfg with authkey + use_aes_gcm
			rep, _ := Encode(mac, factoryKey, false, map[string]any{
				"_type":    "setparam",
				"mgmt_cfg": "authkey=" + newKeyHex + "\nuse_aes_gcm=true\ncfgversion=aaa111\n",
			})
			w.Write(rep)
		case 3:
			// Must now arrive encrypted with adoptedKey + GCM
			got, err := Decode(adoptedKey, true, body)
			if err != nil {
				t.Fatalf("step 3 expected GCM with adopted key: %v", err)
			}
			if got["cfgversion"] != "aaa111" || got["default"] != false {
				t.Fatalf("step 3 unexpected payload: %v", got)
			}
			// Send system_cfg + new cfgversion
			rep, _ := Encode(mac, adoptedKey, true, map[string]any{
				"_type":      "setparam",
				"cfgversion": "bbb222",
				"system_cfg": `{"udapi":{"version":1}}`,
			})
			w.Write(rep)
		case 4:
			// Confirm cfgversion echoed; offer upgrade
			got, err := Decode(adoptedKey, true, body)
			if err != nil || got["cfgversion"] != "bbb222" {
				t.Fatalf("step 4 bad payload: %v err=%v", got, err)
			}
			rep, _ := Encode(mac, adoptedKey, true, map[string]any{
				"_type":   "upgrade",
				"version": "6.1.0.99999",
				"url":     "https://fw-download.ubnt.com/fake.bin",
			})
			w.Write(rep)
		case 5:
			// Confirm offered version reported back; reply noop
			got, err := Decode(adoptedKey, true, body)
			if err != nil || got["version"] != "6.1.0.99999" {
				t.Fatalf("step 5 expected reported version 6.1.0.99999, got %v err=%v", got["version"], err)
			}
			rep, _ := Encode(mac, adoptedKey, true, map[string]any{
				"_type":    "noop",
				"interval": 15,
			})
			w.Write(rep)
		}
	}))
	defer srv.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	st := &config.State{CfgVersion: "0"}
	cli := NewClient(srv.URL+"/inform", st, statePath, 10*time.Second, log.New(io.Discard, "", 0))

	for i := 1; i <= 5; i++ {
		res, err := cli.Send(macStr, map[string]any{"version": "6.0.17.36539"})
		if err != nil {
			t.Fatalf("step %d error: %v", i, err)
		}
		if i == 5 && (res.ReplyType != "noop" || res.NextInterval != 15*time.Second) {
			t.Fatalf("step 5 unexpected result: %+v", res)
		}
	}

	// Verify state persisted to disk
	reloaded, err := config.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Adopted || !reloaded.UseGCM || reloaded.AuthKeyHex != newKeyHex || reloaded.CfgVersion != "bbb222" || reloaded.ReportedVersion != "6.1.0.99999" {
		t.Fatalf("unexpected persisted state: %+v", reloaded)
	}
}
