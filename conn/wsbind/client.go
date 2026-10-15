/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 christarcher. All Rights Reserved.
 */

package wsbind

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"golang.zx2c4.com/wireguard/conn"
)

// ClientEndpoint is a server URL that a client connects to. All peers with
// the same URL share one endpoint and one connection.
type ClientEndpoint struct {
	c *client
}

var _ conn.Endpoint = (*ClientEndpoint)(nil)

func (e *ClientEndpoint) ClearSrc()           {}
func (e *ClientEndpoint) SrcToString() string { return "" }
func (e *ClientEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// DstToString returns the server's address while connected, and the host and
// port of the URL otherwise. It never returns the URL itself, since wg(8)
// expects a host:port.
func (e *ClientEndpoint) DstToString() string {
	if ap := e.c.remote.Load(); ap != nil {
		return ap.String()
	}
	return e.c.hostPort
}

func (e *ClientEndpoint) DstIP() netip.Addr {
	if ap := e.c.remote.Load(); ap != nil {
		return ap.Addr()
	}
	if ap, err := netip.ParseAddrPort(e.c.hostPort); err == nil {
		return ap.Addr()
	}
	return netip.IPv4Unspecified()
}

func (e *ClientEndpoint) DstToBytes() []byte { return []byte(e.c.key) }

// URL returns the server URL, without credentials.
func (e *ClientEndpoint) URL() string { return e.c.display }

func isWSURL(s string) bool {
	s = strings.ToLower(s)
	return strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://")
}

// parseWSURL parses a ws:// or wss:// URL. It returns the URL with any
// credentials removed, and the request header that carries them.
func parseWSURL(s string) (*url.URL, http.Header, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, nil, err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, nil, fmt.Errorf("URL %q must use ws:// or wss://", s)
	}
	if u.Hostname() == "" {
		return nil, nil, fmt.Errorf("URL %q has no host", s)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	header := make(http.Header)
	if u.User != nil {
		password, _ := u.User.Password()
		auth := u.User.Username() + ":" + password
		header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		u.User = nil
	}
	return u, header, nil
}

// client manages the connection to one server URL.
type client struct {
	b        *Bind
	key      string // the URL as given, which identifies the client
	url      string // without credentials
	display  string // for logs
	hostPort string
	header   http.Header
	ep       *ClientEndpoint
	remote   atomic.Pointer[netip.AddrPort] // the server's address while connected

	mu       sync.Mutex
	conn     *wsConn
	dialing  bool
	pending  [][]byte // packets queued while dialing
	delay    time.Duration
	nextDial time.Time
}

// clientFor returns the client for rawURL, creating it if needed.
func (b *Bind) clientFor(rawURL string) (*client, error) {
	u, header, err := parseWSURL(rawURL)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if c, ok := b.clients[rawURL]; ok {
		return c, nil
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "wss" {
			port = "443"
		}
	}
	c := &client{
		b:        b,
		key:      rawURL,
		url:      u.String(),
		display:  u.Redacted(),
		hostPort: net.JoinHostPort(u.Hostname(), port),
		header:   header,
	}
	c.ep = &ClientEndpoint{c: c}
	b.clients[rawURL] = c
	return c, nil
}

// send writes bufs to the server, or queues them and starts dialing if there
// is no connection. Packets are dropped while a failed dial is backing off.
func (c *client) send(s *session, bufs [][]byte) {
	c.mu.Lock()
	wc := c.conn
	if wc != nil && wc.isClosed() {
		wc = nil
		c.conn = nil
	}
	if wc == nil {
		if !c.dialing && !time.Now().Before(c.nextDial) {
			c.dialing = true
			go c.dial(s)
		}
		if c.dialing {
			for _, buf := range bufs {
				if len(c.pending) >= maxPendingPackets {
					break
				}
				c.pending = append(c.pending, append([]byte(nil), buf...))
			}
		}
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	if err := wc.write(bufs); err != nil {
		c.b.verbosef("Failed to send to %s: %v", c.display, err)
	}
}

func (c *client) dial(s *session) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	go func() {
		select {
		case <-s.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	mark := c.b.currentMark()
	var raw net.Conn
	dialer := websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Control: func(network, address string, rc syscall.RawConn) error {
				return controlMark(rc, mark)
			}}
			nc, err := d.DialContext(ctx, network, addr)
			raw = nc
			return nc, err
		},
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: c.b.opts.InsecureSkipVerify},
		HandshakeTimeout: dialTimeout,
		ReadBufferSize:   bufferSize,
		WriteBufferSize:  bufferSize,
		WriteBufferPool:  &sync.Pool{},
	}
	ws, resp, err := dialer.DialContext(ctx, c.url, c.header)

	c.mu.Lock()
	c.dialing = false
	if s.isClosed() {
		// The bind was closed while dialing, which is not the server's
		// fault. Keep the pending packets for the next session, which dials
		// again on its first send.
		c.mu.Unlock()
		if ws != nil {
			ws.Close()
		}
		return
	}
	if err != nil {
		if resp != nil {
			err = fmt.Errorf("%w (HTTP status %s)", err, resp.Status)
		}
		c.pending = nil
		c.delay = min(max(2*c.delay, minRedialDelay), maxRedialDelay)
		c.nextDial = time.Now().Add(c.delay)
		c.mu.Unlock()
		c.b.errorf("Failed to connect to %s: %v", c.display, err)
		return
	}
	wc := newWSConn(ws, raw)
	if !s.add(wc) {
		// The session closed after the check above.
		c.mu.Unlock()
		wc.close()
		return
	}
	// Hold the write lock until the pending packets are out, so that they
	// precede anything sent once c.conn is visible.
	wc.writeMu.Lock()
	c.conn = wc
	c.delay = 0
	c.nextDial = time.Time{}
	pending := c.pending
	c.pending = nil
	if ap, err := netip.ParseAddrPort(raw.RemoteAddr().String()); err == nil {
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		c.remote.Store(&ap)
	}
	c.mu.Unlock()

	c.b.verbosef("Connected to %s (%s)", c.display, raw.RemoteAddr())
	err = wc.writeLocked(pending)
	wc.writeMu.Unlock()
	if err != nil {
		c.b.verbosef("Failed to send to %s: %v", c.display, err)
	}

	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(clientReadTimeout))
		return nil
	})
	go wc.pingLoop()
	go func() {
		err := c.b.readLoop(s, wc, c.ep, clientReadTimeout)
		s.remove(wc)
		c.mu.Lock()
		if c.conn == wc {
			c.conn = nil
			c.remote.Store(nil)
		}
		c.mu.Unlock()
		switch {
		case s.isClosed():
		case isExpectedClose(err):
			c.b.verbosef("Disconnected from %s", c.display)
		default:
			c.b.errorf("Disconnected from %s: %v", c.display, err)
		}
	}()
}

// pingLoop pings the server so that idle connections are kept open by
// proxies along the way and dead ones are detected.
func (c *wsConn) pingLoop() {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			err := c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(controlTimeout))
			if err != nil && !errors.Is(err, websocket.ErrCloseSent) {
				c.close()
				return
			}
		}
	}
}
