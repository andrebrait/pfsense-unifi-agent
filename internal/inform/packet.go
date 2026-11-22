package inform

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// FactoryKeyHex is MD5("ubnt"), the factory default inform encryption key.
	FactoryKeyHex = "ba86f2bbe107c7c57eb5f2690775c712"

	HeaderLen = 40

	FlagEncrypted uint16 = 0x01
	FlagZlib      uint16 = 0x02
	FlagSnappy    uint16 = 0x04
	FlagGCM       uint16 = 0x08
)

var magic = [4]byte{'T', 'N', 'B', 'U'}

// ParseMAC parses a colon- or dash-separated or bare 12-hex MAC address into 6 bytes.
func ParseMAC(s string) ([6]byte, error) {
	var out [6]byte
	clean := strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.TrimSpace(s))
	if len(clean) != 12 {
		return out, fmt.Errorf("invalid MAC %q", s)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return out, fmt.Errorf("invalid MAC %q: %w", s, err)
	}
	copy(out[:], b)
	return out, nil
}

// ParseKey decodes a 32-hex-char (16-byte) AES-128 inform authkey.
func ParseKey(hexKey string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(b) != 16 {
		return nil, fmt.Errorf("authkey must be 32 hex chars (got len=%d)", len(strings.TrimSpace(hexKey)))
	}
	return b, nil
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	n := blockSize - (len(b) % blockSize)
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, errors.New("invalid padded length")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, fmt.Errorf("invalid pkcs7 padding byte %d", n)
	}
	for i := len(b) - n; i < len(b); i++ {
		if int(b[i]) != n {
			return nil, errors.New("corrupt pkcs7 padding")
		}
	}
	return b[:len(b)-n], nil
}

// Encode serializes payload as JSON, compresses with zlib, and wraps it in a TNBU frame
// encrypted with AES-128-GCM (when useGCM is true) or AES-128-CBC.
func Encode(mac [6]byte, key []byte, useGCM bool, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal inform payload: %w", err)
	}
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	plain := zbuf.Bytes()

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generate iv: %w", err)
	}

	flags := FlagEncrypted | FlagZlib
	if useGCM {
		flags |= FlagGCM
	}

	hdr := make([]byte, HeaderLen)
	copy(hdr[0:4], magic[:])
	binary.BigEndian.PutUint32(hdr[4:8], 0) // packet version
	copy(hdr[8:14], mac[:])
	binary.BigEndian.PutUint16(hdr[14:16], flags)
	copy(hdr[16:32], iv)
	binary.BigEndian.PutUint32(hdr[32:36], 1) // data version

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var ct []byte
	if useGCM {
		gcm, err := cipher.NewGCMWithNonceSize(block, 16)
		if err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint32(hdr[36:40], uint32(len(plain)+gcm.Overhead()))
		ct = gcm.Seal(nil, iv, plain, hdr)
	} else {
		padded := pkcs7Pad(plain, aes.BlockSize)
		ct = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
		binary.BigEndian.PutUint32(hdr[36:40], uint32(len(ct)))
	}

	out := make([]byte, HeaderLen+len(ct))
	copy(out[:HeaderLen], hdr)
	copy(out[HeaderLen:], ct)
	return out, nil
}

// Decode decrypts and decompresses a controller TNBU response frame.
// It always refuses unencrypted frames, and refuses CBC frames when requireGCM is true.
func Decode(key []byte, requireGCM bool, pkt []byte) (map[string]any, error) {
	if len(pkt) < HeaderLen {
		return nil, fmt.Errorf("inform packet too short (%d bytes)", len(pkt))
	}
	if !bytes.Equal(pkt[0:4], magic[:]) {
		return nil, fmt.Errorf("bad inform magic %q", pkt[0:4])
	}
	hdr := pkt[:HeaderLen]
	flags := binary.BigEndian.Uint16(hdr[14:16])
	iv := hdr[16:32]
	dataVer := binary.BigEndian.Uint32(hdr[32:36])
	if dataVer != 1 {
		return nil, fmt.Errorf("unsupported data version %d", dataVer)
	}
	plen := binary.BigEndian.Uint32(hdr[36:40])
	if uint64(HeaderLen)+uint64(plen) > uint64(len(pkt)) {
		return nil, fmt.Errorf("truncated inform payload: header says %d bytes, have %d", plen, len(pkt)-HeaderLen)
	}
	ct := pkt[HeaderLen : HeaderLen+plen]

	if flags&FlagEncrypted == 0 {
		return nil, errors.New("refusing unencrypted controller reply")
	}
	if flags&FlagSnappy != 0 {
		return nil, errors.New("unsupported snappy compression in controller reply")
	}
	isGCM := flags&FlagGCM != 0
	if requireGCM && !isGCM {
		return nil, errors.New("refusing CBC downgrade after AES-GCM was negotiated")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var plain []byte
	if isGCM {
		gcm, err := cipher.NewGCMWithNonceSize(block, 16)
		if err != nil {
			return nil, err
		}
		plain, err = gcm.Open(nil, iv, ct, hdr)
		if err != nil {
			return nil, fmt.Errorf("aes-gcm decrypt failed: %w", err)
		}
	} else {
		if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
			return nil, fmt.Errorf("invalid cbc ciphertext length %d", len(ct))
		}
		dec := make([]byte, len(ct))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(dec, ct)
		plain, err = pkcs7Unpad(dec, aes.BlockSize)
		if err != nil {
			return nil, fmt.Errorf("aes-cbc unpad failed: %w", err)
		}
	}

	if flags&FlagZlib != 0 {
		zr, err := zlib.NewReader(bytes.NewReader(plain))
		if err != nil {
			return nil, fmt.Errorf("zlib open failed: %w", err)
		}
		defer zr.Close()
		plain, err = io.ReadAll(io.LimitReader(zr, 4<<20))
		if err != nil {
			return nil, fmt.Errorf("zlib read failed: %w", err)
		}
	}

	var out map[string]any
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil, fmt.Errorf("json decode failed: %w", err)
	}
	return out, nil
}
