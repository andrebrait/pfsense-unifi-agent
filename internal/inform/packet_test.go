package inform

import (
	"testing"
)

func TestEncodeDecodeCBCAndGCM(t *testing.T) {
	mac, err := ParseMAC("02:00:00:00:01:02")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseKey(FactoryKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{"_type": "noop", "interval": float64(10)}

	for _, gcm := range []bool{false, true} {
		pkt, err := Encode(mac, key, gcm, in)
		if err != nil {
			t.Fatalf("encode gcm=%v: %v", gcm, err)
		}
		got, err := Decode(key, gcm, pkt)
		if err != nil {
			t.Fatalf("decode gcm=%v: %v", gcm, err)
		}
		if got["_type"] != "noop" || got["interval"] != float64(10) {
			t.Fatalf("mismatch gcm=%v: %#v", gcm, got)
		}
	}
}

func TestRefuseCBCDowngradeAndTamper(t *testing.T) {
	mac, _ := ParseMAC("02:00:00:00:01:02")
	key, _ := ParseKey(FactoryKeyHex)
	in := map[string]any{"_type": "setdefault"}

	cbcPkt, err := Encode(mac, key, false, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(key, true, cbcPkt); err == nil {
		t.Fatal("expected error refusing CBC downgrade when requireGCM=true")
	}

	gcmPkt, err := Encode(mac, key, true, in)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the header (AAD) — GCM must reject.
	gcmPkt[8] ^= 0x01
	if _, err := Decode(key, true, gcmPkt); err == nil {
		t.Fatal("expected GCM failure on tampered AAD header")
	}
}
