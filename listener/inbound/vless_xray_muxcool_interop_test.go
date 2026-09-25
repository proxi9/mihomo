package inbound_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// TestVLESSMuxCoolXrayInterop sends parallel TCP streams and UDP (XUDP) through
// the mux.cool client to a stock Xray-core VLESS+REALITY server.
func TestVLESSMuxCoolXrayInterop(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at an Xray-core executable")
	}
	origin := startTLSMirrorInteropCarrierTLS(t, padRealityCarrierCertificate)
	tcpEcho := startVMessInteropEcho(t)
	udpEcho := startMuxCoolUDPEcho(t)
	xrayPort := vmessInteropReserveTCPPort(t)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	config, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": xrayPort.Port(), "protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{map[string]any{"id": xrayRealityPlainUUID}},
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

	vless, err := outbound.NewVless(outbound.VlessOption{
		Name:              "vless_muxcool_xray",
		Server:            "127.0.0.1",
		Port:              xrayPort.Port(),
		UUID:              xrayRealityPlainUUID,
		TLS:               true,
		UDP:               true,
		ServerName:        "localhost",
		ClientFingerprint: "chrome",
		RealityOpts: outbound.RealityOptions{
			PublicKey: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
			ShortID:   xrayRealityShortID,
		},
	})
	require.NoError(t, err)
	out, err := outbound.NewMuxCool(outbound.MuxCoolOption{Enabled: true}, vless)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Old REALITY servers reject the first X25519MLKEM768 hello; the client then
	// switches to the classic one (TestVLESSRealityXrayHelloFallback).
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if conn, err := out.DialContext(warmCtx, vmessInteropMetadata(t, tcpEcho)); err == nil {
		_ = conn.Close()
	}
	warmCancel()

	t.Run("tcp", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := out.DialContext(ctx, vmessInteropMetadata(t, tcpEcho))
				if err != nil {
					errs <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte{byte(i)}, 64*1024)
				go func() { _, _ = conn.Write(payload) }()
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(got, payload) {
					errs <- fmt.Errorf("stream %d: echo mismatch", i)
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
	})

	t.Run("udp", func(t *testing.T) {
		metadata := vmessInteropMetadata(t, udpEcho)
		metadata.NetWork = C.UDP
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pc, err := out.ListenPacketContext(ctx, metadata)
		require.NoError(t, err)
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
		addr := net.UDPAddrFromAddrPort(metadata.AddrPort())
		buf := make([]byte, 2048)
		for i := 0; i < 8; i++ {
			payload := []byte(fmt.Sprintf("xudp-%d", i))
			_, err = pc.WriteTo(payload, addr)
			require.NoError(t, err)
			n, _, err := pc.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, payload, buf[:n])
		}
	})
}

func startMuxCoolUDPEcho(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().String()
}
