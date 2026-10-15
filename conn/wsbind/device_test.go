/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 christarcher. All Rights Reserved.
 */

package wsbind_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"golang.zx2c4.com/wireguard/conn/wsbind"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

type testNode struct {
	dev *device.Device
	tun *tuntest.ChannelTUN
	ip  netip.Addr
}

func genKey(t *testing.T) (private, public string) {
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatal(err)
	}
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sk[:]), hex.EncodeToString(pk)
}

func newNode(t *testing.T, name string, ip netip.Addr, opts wsbind.Options, uapi string) testNode {
	t.Helper()
	logf := wsbind.NewTestLogger(t, name)
	logger := &device.Logger{Verbosef: logf, Errorf: logf}
	opts.Verbosef, opts.Errorf = logger.Verbosef, logger.Errorf
	bind, err := wsbind.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	n := testNode{tun: tuntest.NewChannelTUN(), ip: ip}
	n.dev = device.NewDevice(n.tun.TUN(), bind, logger)
	t.Cleanup(n.dev.Close)
	if err := n.dev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	if err := n.dev.Up(); err != nil {
		t.Fatal(err)
	}
	return n
}

// uapiValue returns the first value of key in the device's configuration.
func uapiValue(t *testing.T, dev *device.Device, key string) string {
	t.Helper()
	cfg, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(cfg, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			return v
		}
	}
	return ""
}

func ping(t *testing.T, from, to testNode, timeout time.Duration) {
	t.Helper()
	msg := tuntest.Ping(to.ip, from.ip)
	from.tun.Outbound <- msg
	deadline := time.After(timeout)
	// Resend periodically: like UDP, packets sent while the transport is
	// reconnecting are lost.
	resend := time.NewTicker(time.Second)
	defer resend.Stop()
	for {
		select {
		case got := <-to.tun.Inbound:
			if !bytes.Equal(got, msg) {
				t.Fatalf("ping from %v to %v arrived corrupted", from.ip, to.ip)
			}
			// Drain duplicates from resends.
			for {
				select {
				case <-to.tun.Inbound:
				case <-time.After(50 * time.Millisecond):
					return
				}
			}
		case <-resend.C:
			select {
			case from.tun.Outbound <- msg:
			default:
			}
		case <-deadline:
			t.Fatalf("ping from %v to %v did not arrive", from.ip, to.ip)
		}
	}
}

func TestDevicesOverWebSocket(t *testing.T) {
	serverPriv, serverPub := genKey(t)
	clientPriv, clientPub := genKey(t)
	serverIP, clientIP := netip.MustParseAddr("10.9.0.1"), netip.MustParseAddr("10.9.0.2")

	server := newNode(t, "server", serverIP,
		wsbind.Options{Mode: wsbind.ModeServer, ListenAddr: "127.0.0.1", Path: "/wg"},
		fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\n", serverPriv, clientPub, clientIP))
	port := uapiValue(t, server.dev, "listen_port")
	if port == "" || port == "0" {
		t.Fatalf("server listen port is %q", port)
	}

	// The client's peer has no endpoint; the bind supplies the server URL.
	client := newNode(t, "client", clientIP,
		wsbind.Options{Mode: wsbind.ModeClient, URL: "ws://127.0.0.1:" + port + "/wg"},
		fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=%s/32\n", clientPriv, serverPub, serverIP))
	if got := uapiValue(t, client.dev, "endpoint"); got != "127.0.0.1:"+port {
		t.Errorf("client endpoint is %q, want 127.0.0.1:%s", got, port)
	}
	if got := uapiValue(t, client.dev, "listen_port"); got != "" {
		t.Errorf("client reports listen port %q", got)
	}

	ping(t, client, server, 5*time.Second)
	ping(t, server, client, 5*time.Second)
	if got := uapiValue(t, server.dev, "endpoint"); !strings.HasPrefix(got, "127.0.0.1:") {
		t.Errorf("server learned client endpoint %q", got)
	}

	t.Run("client restart", func(t *testing.T) {
		if err := client.dev.Down(); err != nil {
			t.Fatal(err)
		}
		if err := client.dev.Up(); err != nil {
			t.Fatal(err)
		}
		ping(t, client, server, 10*time.Second)
		ping(t, server, client, 5*time.Second)
	})

	t.Run("server restart", func(t *testing.T) {
		if testing.Short() {
			t.Skip("waits for WireGuard to notice the lost session")
		}
		if err := server.dev.Down(); err != nil {
			t.Fatal(err)
		}
		if err := server.dev.Up(); err != nil {
			t.Fatal(err)
		}
		if got := uapiValue(t, server.dev, "listen_port"); got != port {
			t.Fatalf("server came back on port %s, want %s", got, port)
		}
		// The client redials at once, but its session keys died with the
		// server's, so it takes WireGuard's usual Keepalive-Timeout +
		// Rekey-Timeout without replies before it handshakes again.
		ping(t, client, server, 30*time.Second)
		ping(t, server, client, 5*time.Second)
	})
}
