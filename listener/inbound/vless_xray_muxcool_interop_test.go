package inbound_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

const (
	muxCoolXrayPlainUUID  = "5e3c3a1e-7f5b-4c6e-9d1a-2b8f4e6a0c11"
	muxCoolXrayVisionUUID = "9b0d2f4a-1c3e-4a5b-8d7f-6e5c4b3a2f10"
)

// TestVLESSMuxCoolXrayInterop sends parallel TCP streams and UDP (XUDP) through
// the mux.cool client to a stock Xray-core VLESS+TLS server, for a plain user
// and for a Vision user (Xray muxes only UDP for Vision). It uses plain TLS, not
// REALITY, so the mux.cool patches can be tested and dropped on their own.
func TestVLESSMuxCoolXrayInterop(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at an Xray-core executable")
	}
	tcpEcho := startVMessInteropEcho(t)
	udpEcho := startMuxCoolUDPEcho(t)
	xrayPort := vmessInteropReserveTCPPort(t)
	certLines, keyLines := muxCoolSelfSignedCert(t)
	config, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": xrayPort.Port(), "protocol": "vless",
			"settings": map[string]any{
				"clients": []any{
					map[string]any{"id": muxCoolXrayPlainUUID},
					map[string]any{"id": muxCoolXrayVisionUUID, "flow": "xtls-rprx-vision"},
				},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "tls",
				"tlsSettings": map[string]any{
					"certificates": []any{map[string]any{"certificate": certLines, "key": keyLines}},
				},
			},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}},
	})
	require.NoError(t, err)
	startMuxCoolXray(t, xrayBinary, config, xrayPort)

	for _, user := range []struct{ name, uuid, flow string }{
		{"plain", muxCoolXrayPlainUUID, ""},
		{"vision", muxCoolXrayVisionUUID, "xtls-rprx-vision"},
	} {
		t.Run(user.name, func(t *testing.T) {
			vless, err := outbound.NewVless(outbound.VlessOption{
				Name:              "vless_muxcool_xray",
				Server:            "127.0.0.1",
				Port:              xrayPort.Port(),
				UUID:              user.uuid,
				Flow:              user.flow,
				TLS:               true,
				UDP:               true,
				ServerName:        "localhost",
				SkipCertVerify:    true,
				ClientFingerprint: "chrome",
			})
			require.NoError(t, err)
			out, err := outbound.NewMuxCool(outbound.MuxCoolOption{Enabled: true}, vless)
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

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
		})
	}
}

func muxCoolSelfSignedCert(t *testing.T) (certLines, keyLines []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	lines := func(block *pem.Block) []string {
		return strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(block))), "\n")
	}
	return lines(&pem.Block{Type: "CERTIFICATE", Bytes: der}), lines(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func startMuxCoolXray(t *testing.T, xrayBinary string, config []byte, port *vmessInteropReservedTCPPort) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "xray.json")
	require.NoError(t, os.WriteFile(configPath, config, 0o600))
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, xrayBinary, "run", "-c", configPath)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	port.Release()
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		cancel()
		<-done
		if t.Failed() {
			t.Log(output.String())
		}
	})
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(port.Port()))
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
			_ = conn.Close()
			return
		}
	}
	t.Fatalf("Xray did not listen on %s\n%s", address, output.String())
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
