package inbound_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/stretchr/testify/require"
)

// TestVLESSRealityXrayHelloFallback checks that the default chrome fingerprint
// reaches any REALITY server generation by the second dial: Xray before 25
// rejects X25519MLKEM768, Xray 26.9.8+ requires it.
func TestVLESSRealityXrayHelloFallback(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at an Xray-core executable of any version")
	}
	origin := startTLSMirrorInteropCarrierTLS(t, padRealityCarrierCertificate)
	echoAddr := startVMessInteropEcho(t)
	xrayPort := vmessInteropReserveTCPPort(t)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	// "dest" instead of "target": Xray 1.8 knows only the former.
	config, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": xrayPort.Port(), "protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{map[string]any{"id": xrayRealityVisionUUID, "flow": "xtls-rprx-vision"}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{
					"dest":        origin.addr,
					"serverNames": []string{"localhost"},
					"privateKey":  base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
					"shortIds":    []string{xrayRealityShortID},
				},
			},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}},
	})
	require.NoError(t, err)
	startXrayRealityServer(t, xrayBinary, config, xrayPort)

	out, err := outbound.NewVless(outbound.VlessOption{
		Name:              "vless_reality_fallback",
		Server:            "127.0.0.1",
		Port:              xrayPort.Port(),
		UUID:              xrayRealityVisionUUID,
		Flow:              "xtls-rprx-vision",
		TLS:               true,
		ServerName:        "localhost",
		ClientFingerprint: "chrome",
		RealityOpts: outbound.RealityOptions{
			PublicKey: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
			ShortID:   xrayRealityShortID,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	echo := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, vmessInteropMetadata(t, echoAddr))
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		payload := []byte("reality-fallback")
		if _, err = conn.Write(payload); err != nil {
			return err
		}
		_, err = io.ReadFull(conn, make([]byte, len(payload)))
		return err
	}
	if err := echo(); err != nil {
		t.Logf("first dial: %v", err)
	}
	require.NoError(t, echo(), "second dial")
	require.NoError(t, echo(), "third dial")
}
