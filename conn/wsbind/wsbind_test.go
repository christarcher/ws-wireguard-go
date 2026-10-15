/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 christarcher. All Rights Reserved.
 */

package wsbind

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// NewTestLogger returns a log function that writes to t until t's cleanup runs.
// Goroutines that outlive a test, such as device workers that log as they
// stop, must not call t.Logf after the test completes.
func NewTestLogger(t testing.TB, name string) func(string, ...any) {
	var mu sync.Mutex
	done := false
	t.Cleanup(func() {
		mu.Lock()
		done = true
		mu.Unlock()
	})
	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if !done {
			t.Logf(name+": "+format, args...)
		}
	}
}

func newTestServer(t testing.TB, opts Options) (*Bind, conn.ReceiveFunc, uint16) {
	t.Helper()
	opts.Mode = ModeServer
	if opts.ListenAddr == "" {
		opts.ListenAddr = "127.0.0.1"
	}
	opts.Verbosef = NewTestLogger(t, "server")
	opts.Errorf = opts.Verbosef
	b, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fns) != 1 || port == 0 {
		t.Fatalf("Open returned %d receive funcs and port %d", len(fns), port)
	}
	t.Cleanup(func() { b.Close() })
	return b, fns[0], port
}

func newTestClient(t testing.TB, url string) (*Bind, conn.ReceiveFunc) {
	t.Helper()
	b, err := New(Options{Mode: ModeClient, URL: url, Verbosef: NewTestLogger(t, "client"), Errorf: NewTestLogger(t, "client")})
	if err != nil {
		t.Fatal(err)
	}
	fns, port, err := b.Open(51820)
	if err != nil {
		t.Fatal(err)
	}
	if len(fns) != 1 || port != 0 {
		t.Fatalf("client Open returned %d receive funcs and port %d", len(fns), port)
	}
	t.Cleanup(func() { b.Close() })
	return b, fns[0]
}

type received struct {
	packets [][]byte
	eps     []conn.Endpoint
	err     error
}

// receive calls fn once in the background.
func receive(fn conn.ReceiveFunc) chan received {
	ch := make(chan received, 1)
	go func() {
		bufs := make([][]byte, conn.IdealBatchSize)
		for i := range bufs {
			bufs[i] = make([]byte, maxPacketSize)
		}
		sizes := make([]int, len(bufs))
		eps := make([]conn.Endpoint, len(bufs))
		n, err := fn(bufs, sizes, eps)
		var r received
		r.err = err
		for i := 0; i < n; i++ {
			r.packets = append(r.packets, bufs[i][:sizes[i]])
			r.eps = append(r.eps, eps[i])
		}
		ch <- r
	}()
	return ch
}

// receiveN receives exactly n packets from fn.
func receiveN(t testing.TB, fn conn.ReceiveFunc, n int) received {
	t.Helper()
	var all received
	timeout := time.After(10 * time.Second)
	for len(all.packets) < n {
		select {
		case r := <-receive(fn):
			if r.err != nil {
				t.Fatalf("receive: %v", r.err)
			}
			all.packets = append(all.packets, r.packets...)
			all.eps = append(all.eps, r.eps...)
		case <-timeout:
			t.Fatalf("received %d of %d packets", len(all.packets), n)
		}
	}
	return all
}

func testPackets(prefix string, n int) [][]byte {
	var packets [][]byte
	for i := 0; i < n; i++ {
		packets = append(packets, []byte(fmt.Sprintf("%s %d", prefix, i)))
	}
	return packets
}

func checkPackets(t testing.TB, got, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d packets, want %d", len(got), len(want))
	}
	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("packet %d is %q, want %q", i, got[i], want[i])
		}
	}
}

func checkGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		deadline := time.Now().Add(5 * time.Second)
		for runtime.NumGoroutine() > before {
			if time.Now().After(deadline) {
				buf := make([]byte, 1<<20)
				t.Errorf("%d goroutines before, %d after:\n%s", before, runtime.NumGoroutine(), buf[:runtime.Stack(buf, true)])
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func TestRoundTrip(t *testing.T) {
	checkGoroutines(t)
	server, serverRecv, port := newTestServer(t, Options{Path: "/wg"})
	client, clientRecv := newTestClient(t, fmt.Sprintf("ws://127.0.0.1:%d/wg", port))

	clientEP := client.DefaultEndpoint()
	if clientEP == nil {
		t.Fatal("client has no default endpoint")
	}
	if got, want := clientEP.DstToString(), fmt.Sprintf("127.0.0.1:%d", port); got != want {
		t.Errorf("client endpoint is %s before connecting, want %s", got, want)
	}

	// The client queues these while it dials, and must deliver them in order.
	up := testPackets("up", 20)
	if err := client.Send(up, clientEP); err != nil {
		t.Fatal(err)
	}
	r := receiveN(t, serverRecv, len(up))
	checkPackets(t, r.packets, up)
	serverEP := r.eps[0]
	if _, ok := serverEP.(*ServerEndpoint); !ok {
		t.Fatalf("server received from %T", serverEP)
	}
	if !serverEP.DstIP().IsLoopback() {
		t.Errorf("server endpoint is %s, want a loopback address", serverEP.DstToString())
	}
	if got := clientEP.DstToString(); got != fmt.Sprintf("127.0.0.1:%d", port) {
		t.Errorf("client endpoint is %s while connected", got)
	}

	// A maximum-size packet followed by a batch, back over the accepted connection.
	big := bytes.Repeat([]byte{0xa5}, maxPacketSize)
	down := append([][]byte{big}, testPackets("down", 3*conn.IdealBatchSize)...)
	for i := 0; i < len(down); i += conn.IdealBatchSize {
		if err := server.Send(down[i:min(i+conn.IdealBatchSize, len(down))], serverEP); err != nil {
			t.Fatal(err)
		}
	}
	r = receiveN(t, clientRecv, len(down))
	checkPackets(t, r.packets, down)
	for _, ep := range r.eps {
		if ep != clientEP {
			t.Fatalf("client received from %v, want its server endpoint", ep)
		}
	}
}

func TestClose(t *testing.T) {
	checkGoroutines(t)
	server, serverRecv, port := newTestServer(t, Options{})
	client, clientRecv := newTestClient(t, fmt.Sprintf("ws://127.0.0.1:%d", port))
	if err := client.Send([][]byte{[]byte("hello")}, client.DefaultEndpoint()); err != nil {
		t.Fatal(err)
	}
	serverEP := receiveN(t, serverRecv, 1).eps[0]

	pendingServer := receive(serverRecv)
	pendingClient := receive(clientRecv)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for _, ch := range []chan received{pendingServer, pendingClient} {
		select {
		case r := <-ch:
			if !errors.Is(r.err, net.ErrClosed) {
				t.Errorf("receive after Close returned %v, want net.ErrClosed", r.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("receive did not return after Close")
		}
	}
	if err := server.Send([][]byte{[]byte("x")}, serverEP); !errors.Is(err, net.ErrClosed) {
		t.Errorf("server Send after Close returned %v, want net.ErrClosed", err)
	}
	if err := client.Send([][]byte{[]byte("x")}, client.DefaultEndpoint()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("client Send after Close returned %v, want net.ErrClosed", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		t.Error("server still listening after Close")
	}
}

// TestReconnect restarts the server, as happens when the device goes down and
// up or its listen port changes, and checks that the client redials.
func TestReconnect(t *testing.T) {
	checkGoroutines(t)
	server, serverRecv, port := newTestServer(t, Options{})
	client, _ := newTestClient(t, fmt.Sprintf("ws://127.0.0.1:%d/", port))
	ep := client.DefaultEndpoint()
	if err := client.Send([][]byte{[]byte("one")}, ep); err != nil {
		t.Fatal(err)
	}
	receiveN(t, serverRecv, 1)

	server.Close()
	fns, newPort, err := server.Open(port)
	if err != nil {
		t.Fatal(err)
	}
	if newPort != port {
		t.Fatalf("server reopened on port %d, want %d", newPort, port)
	}

	// Packets are lost until the client notices and redials, as on a lossy
	// network, so keep sending until one arrives.
	got := receive(fns[0])
	deadline := time.After(10 * time.Second)
	for {
		if err := client.Send([][]byte{[]byte("two")}, ep); err != nil {
			t.Fatal(err)
		}
		select {
		case r := <-got:
			if r.err != nil {
				t.Fatal(r.err)
			}
			checkPackets(t, r.packets[:1], [][]byte{[]byte("two")})
			return
		case <-time.After(100 * time.Millisecond):
		case <-deadline:
			t.Fatal("client did not reconnect")
		}
	}
}

func TestServerOnlyAcceptsWebSocketOnPath(t *testing.T) {
	_, serverRecv, port := newTestServer(t, Options{Path: "/secret"})

	for _, path := range []string{"/secret", "/", "/other"} {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, path))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("plain GET %s returned %s, want 404", path, resp.Status)
		}
	}

	client, _ := newTestClient(t, fmt.Sprintf("ws://127.0.0.1:%d/other", port))
	client.Send([][]byte{[]byte("lost")}, client.DefaultEndpoint())
	select {
	case r := <-receive(serverRecv):
		t.Fatalf("server received %q from a client on the wrong path", r.packets)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestServerEndpointFromUAPI(t *testing.T) {
	server, _, _ := newTestServer(t, Options{})
	ep, err := server.ParseEndpoint("192.0.2.1:51820")
	if err != nil {
		t.Fatal(err)
	}
	if got := ep.DstToString(); got != "192.0.2.1:51820" {
		t.Errorf("endpoint is %s", got)
	}
	if err := server.Send([][]byte{[]byte("x")}, ep); !errors.Is(err, errNotConnected) {
		t.Errorf("Send to an unconnected peer returned %v, want errNotConnected", err)
	}
	if _, err := server.ParseEndpoint("ws://192.0.2.1/"); err == nil {
		t.Error("server accepted a URL endpoint")
	}
	if server.DefaultEndpoint() != nil {
		t.Error("server has a default endpoint")
	}
}

func TestRealIPHeader(t *testing.T) {
	b, err := New(Options{Mode: ModeServer, RealIPHeader: "X-Forwarded-For"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		header []string
		want   string
	}{
		{nil, "127.0.0.1:4000"},
		{[]string{"198.51.100.7"}, "198.51.100.7:4000"},
		{[]string{"203.0.113.9, 198.51.100.7"}, "198.51.100.7:4000"},
		{[]string{"203.0.113.9", "2001:db8::1"}, "[2001:db8::1]:4000"},
		{[]string{"[2001:db8::2]:1234"}, "[2001:db8::2]:1234"},
		{[]string{"garbage"}, "127.0.0.1:4000"},
	} {
		r := &http.Request{RemoteAddr: "127.0.0.1:4000", Header: http.Header{}}
		for _, v := range tt.header {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := b.remoteAddr(r).String(); got != tt.want {
			t.Errorf("X-Forwarded-For %q gave %s, want %s", tt.header, got, tt.want)
		}
	}
}

func TestClientParseEndpoint(t *testing.T) {
	b, err := New(Options{Mode: ModeClient, Path: "/tunnel"})
	if err != nil {
		t.Fatal(err)
	}
	if b.DefaultEndpoint() != nil {
		t.Error("client without URL has a default endpoint")
	}
	for _, tt := range []struct {
		in, url, dst string
	}{
		{"192.0.2.1:8080", "ws://192.0.2.1:8080/tunnel", "192.0.2.1:8080"},
		{"[2001:db8::1]:443", "ws://[2001:db8::1]:443/tunnel", "[2001:db8::1]:443"},
		{"vpn.example.com:80", "ws://vpn.example.com:80/tunnel", "vpn.example.com:80"},
		{"wss://vpn.example.com/wg", "wss://vpn.example.com/wg", "vpn.example.com:443"},
		{"ws://vpn.example.com", "ws://vpn.example.com/", "vpn.example.com:80"},
		{"WSS://user:pw@vpn.example.com:8443/x?y=1", "wss://vpn.example.com:8443/x?y=1", "vpn.example.com:8443"},
	} {
		ep, err := b.ParseEndpoint(tt.in)
		if err != nil {
			t.Errorf("ParseEndpoint(%q): %v", tt.in, err)
			continue
		}
		ce := ep.(*ClientEndpoint)
		if ce.c.url != tt.url || ce.DstToString() != tt.dst {
			t.Errorf("ParseEndpoint(%q) = %s (%s), want %s (%s)", tt.in, ce.c.url, ce.DstToString(), tt.url, tt.dst)
		}
		if strings.Contains(ce.URL(), "pw") {
			t.Errorf("URL() of %q exposes the password: %s", tt.in, ce.URL())
		}
	}
	ep, _ := b.ParseEndpoint("wss://user:pw@vpn.example.com:8443/x?y=1")
	if got, want := ep.(*ClientEndpoint).c.header.Get("Authorization"), "Basic dXNlcjpwdw=="; got != want {
		t.Errorf("Authorization header is %q, want %q", got, want)
	}
	if a, _ := b.ParseEndpoint("192.0.2.1:8080"); a != must(b.ParseEndpoint("192.0.2.1:8080")) {
		t.Error("equal endpoints do not share a connection")
	}
	for _, bad := range []string{"192.0.2.1", "http://vpn.example.com/", "ws:///path", "nonsense"} {
		if _, err := b.ParseEndpoint(bad); err == nil {
			t.Errorf("ParseEndpoint(%q) succeeded", bad)
		}
	}

	// With a server URL, every endpoint is the server.
	b, err = New(Options{Mode: ModeClient, URL: "wss://vpn.example.com/wg"})
	if err != nil {
		t.Fatal(err)
	}
	def := b.DefaultEndpoint()
	if def == nil || def.DstToString() != "vpn.example.com:443" {
		t.Fatalf("default endpoint is %v", def)
	}
	if ep, _ := b.ParseEndpoint("192.0.2.1:51820"); ep != def {
		t.Errorf("host:port endpoint is %v, want the server URL", ep)
	}
	if ep, _ := b.ParseEndpoint("wss://other.example.com/wg"); ep == def {
		t.Error("explicit URL endpoint was replaced by the server URL")
	}
}

func must(ep conn.Endpoint, err error) conn.Endpoint {
	if err != nil {
		panic(err)
	}
	return ep
}

func TestOptionsValidate(t *testing.T) {
	for _, tt := range []struct {
		opts Options
		ok   bool
	}{
		{Options{Mode: ModeServer}, true},
		{Options{Mode: ModeServer, ListenAddr: "127.0.0.1:8080", Path: "/wg"}, true},
		{Options{Mode: ModeServer, ListenAddr: "[::1]"}, true},
		{Options{Mode: ModeServer, ListenAddr: "::1"}, true},
		{Options{Mode: ModeServer, ListenAddr: "127.0.0.1:99999"}, false},
		{Options{Mode: ModeServer, TLSCertFile: "cert.pem"}, false},
		{Options{Mode: ModeServer, URL: "ws://x/"}, false},
		{Options{Mode: ModeServer, Path: "wg"}, false},
		{Options{Mode: ModeClient}, true},
		{Options{Mode: ModeClient, URL: "wss://vpn.example.com/wg"}, true},
		{Options{Mode: ModeClient, URL: "https://vpn.example.com/wg"}, false},
		{Options{Mode: ModeClient, ListenAddr: "127.0.0.1"}, false},
		{Options{}, false},
	} {
		if err := tt.opts.Validate(); (err == nil) != tt.ok {
			t.Errorf("Validate(%+v) = %v, want ok=%v", tt.opts, err, tt.ok)
		}
	}
}

func TestListenAddr(t *testing.T) {
	b, err := New(Options{Mode: ModeServer, ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	// The device's port is used because the listen address has a zero port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	_, got, err := b.Open(port)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if got != port {
		t.Errorf("listening on %d, want %d", got, port)
	}
	if _, _, err := b.Open(port); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Errorf("second Open returned %v", err)
	}
}

// TestConcurrentSend sends from many goroutines at once in both directions.
// Nothing may be lost while connected, since WebSocket runs over TCP and the
// receive queue blocks rather than drops.
func TestConcurrentSend(t *testing.T) {
	checkGoroutines(t)
	server, serverRecv, port := newTestServer(t, Options{})
	client, clientRecv := newTestClient(t, fmt.Sprintf("ws://127.0.0.1:%d/", port))
	clientEP := client.DefaultEndpoint()
	if err := client.Send([][]byte{[]byte("hello")}, clientEP); err != nil {
		t.Fatal(err)
	}
	serverEP := receiveN(t, serverRecv, 1).eps[0]

	const senders, batches, batchSize = 8, 200, 4
	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		for _, side := range []struct {
			b  *Bind
			ep conn.Endpoint
		}{{client, clientEP}, {server, serverEP}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < batches; j++ {
					if err := side.b.Send(testPackets(fmt.Sprintf("%d-%d", i, j), batchSize), side.ep); err != nil {
						t.Error(err)
						return
					}
				}
			}()
		}
	}
	total := senders * batches * batchSize
	for _, fn := range []conn.ReceiveFunc{serverRecv, clientRecv} {
		r := receiveN(t, fn, total)
		seen := make(map[string]bool, total)
		for _, p := range r.packets {
			if seen[string(p)] {
				t.Fatalf("duplicate packet %q", p)
			}
			seen[string(p)] = true
		}
	}
	wg.Wait()
}
