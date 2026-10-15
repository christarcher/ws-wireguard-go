/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 christarcher. All Rights Reserved.
 */

package wsbind

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"golang.zx2c4.com/wireguard/conn"
)

// ServerEndpoint is a WebSocket connection accepted by a server, or, when it
// was configured through UAPI, a placeholder that no connection backs yet.
type ServerEndpoint struct {
	conn *wsConn
	addr netip.AddrPort // the peer's address, possibly from RealIPHeader
}

var _ conn.Endpoint = (*ServerEndpoint)(nil)

func (e *ServerEndpoint) ClearSrc()           {}
func (e *ServerEndpoint) SrcToString() string { return "" }
func (e *ServerEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *ServerEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *ServerEndpoint) DstToString() string { return e.addr.String() }

func (e *ServerEndpoint) DstToBytes() []byte {
	b, _ := e.addr.MarshalBinary()
	return b
}

// splitListenAddr splits a listen address given as "host" or "host:port".
// The port is zero if omitted.
func splitListenAddr(addr string) (host string, port uint16, err error) {
	if addr == "" {
		return "", 0, nil
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		// No port; allow a bare IPv6 address with or without brackets.
		return strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"), 0, nil
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in listen address %q", addr)
	}
	return h, uint16(n), nil
}

// listenLocked starts the HTTP server for session s. The caller must hold b.mu.
func (b *Bind) listenLocked(s *session, port uint16) (uint16, error) {
	host, p, _ := splitListenAddr(b.opts.ListenAddr)
	if p != 0 {
		port = p
	}

	var tlsConfig *tls.Config
	if b.opts.TLSCertFile != "" {
		// Load on every Open so that a renewed certificate is picked up when
		// the device is brought down and up again.
		cert, err := tls.LoadX509KeyPair(b.opts.TLSCertFile, b.opts.TLSKeyFile)
		if err != nil {
			return 0, err
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"http/1.1"},
		}
	}

	mark := b.mark
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return controlMark(c, mark)
	}}
	ln, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return 0, err
	}
	actualPort := uint16(ln.Addr().(*net.TCPAddr).Port)

	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b.serveHTTP(s, w, r) }),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       60 * time.Second, // for plain HTTP keep-alive, not WebSocket
		ErrorLog:          log.New(logWriter(b.verbosef), "", 0),
	}
	served := ln
	if tlsConfig != nil {
		served = tls.NewListener(ln, tlsConfig)
	}
	go func() {
		if err := srv.Serve(served); err != nil && err != http.ErrServerClosed {
			b.errorf("Server stopped: %v", err)
		}
	}()

	scheme := "ws"
	if tlsConfig != nil {
		scheme = "wss"
	}
	b.verbosef("Listening for %s connections on %s, path %s", scheme, ln.Addr(), b.path)
	b.server = srv
	b.listener = ln
	return actualPort, nil
}

func (b *Bind) serveHTTP(s *session, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != b.path || !websocket.IsWebSocketUpgrade(r) {
		http.NotFound(w, r)
		return
	}
	addr := b.remoteAddr(r)
	ws, err := b.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has already replied with an HTTP error.
		b.verbosef("Failed to accept connection from %s: %v", addr, err)
		return
	}
	c := newWSConn(ws, rawConn(ws.NetConn()))
	if !s.add(c) {
		c.close()
		return
	}
	defer s.remove(c)

	ws.SetPingHandler(func(data string) error {
		ws.SetReadDeadline(time.Now().Add(serverReadTimeout))
		err := ws.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(controlTimeout))
		if err == websocket.ErrCloseSent {
			return nil
		}
		return err
	})

	b.verbosef("Accepted connection from %s", addr)
	err = b.readLoop(s, c, &ServerEndpoint{conn: c, addr: addr}, serverReadTimeout)
	if isExpectedClose(err) {
		b.verbosef("Connection from %s closed", addr)
	} else {
		b.verbosef("Connection from %s closed: %v", addr, err)
	}
}

// remoteAddr returns the address of the peer behind r.
func (b *Bind) remoteAddr(r *http.Request) netip.AddrPort {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		ap = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	}
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	if b.opts.RealIPHeader == "" {
		return ap
	}
	values := r.Header.Values(b.opts.RealIPHeader)
	if len(values) == 0 {
		return ap
	}
	// Proxies append to X-Forwarded-For, so the last entry is the one added
	// by the proxy in front of us; earlier entries came from the client.
	v := values[len(values)-1]
	if i := strings.LastIndexByte(v, ','); i >= 0 {
		v = v[i+1:]
	}
	v = strings.TrimSpace(v)
	if real, err := netip.ParseAddrPort(v); err == nil {
		return netip.AddrPortFrom(real.Addr().Unmap(), real.Port())
	}
	if real, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")); err == nil {
		// Keep the proxy's port, which tells apart connections from one address.
		return netip.AddrPortFrom(real.Unmap(), ap.Port())
	}
	return ap
}

// rawConn returns the TCP connection beneath c.
func rawConn(c net.Conn) net.Conn {
	if tc, ok := c.(*tls.Conn); ok {
		return tc.NetConn()
	}
	return c
}

// logWriter adapts a log function to an io.Writer for log.Logger.
type logWriter func(format string, args ...any)

func (f logWriter) Write(p []byte) (int, error) {
	f("%s", strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}
