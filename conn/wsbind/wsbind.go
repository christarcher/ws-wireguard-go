/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 christarcher. All Rights Reserved.
 */

// Package wsbind implements a conn.Bind that carries WireGuard packets over
// WebSocket connections instead of UDP datagrams.
//
// A Bind runs in one of two modes. In server mode it only accepts WebSocket
// connections and never initiates any; each accepted connection becomes an
// endpoint, which the device roams onto whichever peer authenticates over it.
// In client mode it never listens; it dials the server on demand when a packet
// is sent to a peer and redials whenever the connection is lost.
//
// Each WireGuard packet is carried as one binary WebSocket message. Like UDP,
// the transport is lossy from the device's point of view: packets sent while
// no connection is available are dropped, and the WireGuard protocol recovers
// through its usual retransmission and keepalive timers.
package wsbind

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"golang.zx2c4.com/wireguard/conn"
)

type Mode int

const (
	ModeServer Mode = iota + 1
	ModeClient
)

func (m Mode) String() string {
	switch m {
	case ModeServer:
		return "server"
	case ModeClient:
		return "client"
	}
	return fmt.Sprintf("Mode(%d)", int(m))
}

// ParseMode parses "server" or "client".
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(s) {
	case "server":
		return ModeServer, nil
	case "client":
		return ModeClient, nil
	}
	return 0, fmt.Errorf("invalid mode %q, must be \"server\" or \"client\"", s)
}

// Options configures a Bind.
type Options struct {
	Mode Mode

	// Path is the HTTP path of the WebSocket endpoint. In server mode,
	// connections are only accepted on this path. In client mode, it is used to
	// build the URL for peers whose endpoint is a plain host:port. Defaults to "/".
	Path string

	// ListenAddr is the server's listen address, as "host" or "host:port". If
	// the port is omitted or zero, the device's listen port is used. An empty
	// host listens on all addresses.
	ListenAddr string

	// TLSCertFile and TLSKeyFile make the server speak wss:// directly. They are
	// usually left empty when TLS is terminated by a reverse proxy.
	TLSCertFile string
	TLSKeyFile  string

	// RealIPHeader names a request header, such as X-Forwarded-For or
	// X-Real-IP, set by a trusted reverse proxy. The server takes the peer's
	// address from its last value. Only set this when the server is reachable
	// solely through that proxy, since clients can otherwise forge it.
	RealIPHeader string

	// URL is the ws:// or wss:// server URL. In client mode it becomes the
	// endpoint of every peer, including peers configured without an endpoint
	// or with a plain host:port one. Peers may still be given their own
	// ws(s):// URL through UAPI. Credentials in the URL are sent as HTTP basic
	// authentication.
	URL string

	// InsecureSkipVerify disables verification of the server's TLS certificate.
	InsecureSkipVerify bool

	// Verbosef and Errorf receive log messages. Either may be nil.
	Verbosef func(format string, args ...any)
	Errorf   func(format string, args ...any)
}

// Validate reports whether the options are consistent.
func (o *Options) Validate() error {
	if o.Path != "" && !strings.HasPrefix(o.Path, "/") {
		return fmt.Errorf("path %q must begin with /", o.Path)
	}
	switch o.Mode {
	case ModeServer:
		if (o.TLSCertFile == "") != (o.TLSKeyFile == "") {
			return errors.New("TLS certificate and key must be given together")
		}
		if o.URL != "" {
			return errors.New("a server URL cannot be given in server mode")
		}
		if _, _, err := splitListenAddr(o.ListenAddr); err != nil {
			return err
		}
	case ModeClient:
		if o.ListenAddr != "" || o.TLSCertFile != "" || o.TLSKeyFile != "" || o.RealIPHeader != "" {
			return errors.New("listen address, TLS certificate and real IP header are only valid in server mode")
		}
		if o.URL != "" {
			if _, _, err := parseWSURL(o.URL); err != nil {
				return err
			}
		}
	default:
		return errors.New("mode must be server or client")
	}
	return nil
}

const (
	// maxPacketSize is the largest WireGuard message, matching device.MaxMessageSize.
	maxPacketSize = 1<<16 - 1

	// rxQueueSize is the number of received packets buffered between the
	// connection readers and the device.
	rxQueueSize = 1024

	// maxPendingPackets bounds the packets queued while a client is dialing.
	maxPendingPackets = conn.IdealBatchSize

	dialTimeout    = 15 * time.Second
	writeTimeout   = 15 * time.Second
	controlTimeout = 5 * time.Second

	// The client pings the server every pingInterval. Either side drops a
	// connection on which nothing at all arrived within its read timeout.
	pingInterval      = 20 * time.Second
	clientReadTimeout = 3 * pingInterval
	serverReadTimeout = 4 * pingInterval

	minRedialDelay = 500 * time.Millisecond
	maxRedialDelay = 5 * time.Second

	bufferSize = 16 << 10
)

var (
	errNotConnected = errors.New("peer has not connected to this server")
	errTooLarge     = errors.New("message too large")

	_ conn.Bind              = (*Bind)(nil)
	_ conn.DefaultEndpointer = (*Bind)(nil)
)

// Bind is a conn.Bind over WebSocket connections. See the package
// documentation for details.
type Bind struct {
	opts     Options
	path     string
	upgrader websocket.Upgrader

	mu       sync.Mutex // protects the fields below
	session  *session   // non-nil while open
	mark     uint32
	server   *http.Server
	listener net.Listener // raw TCP listener, for SetMark
	clients  map[string]*client
	defaultE *ClientEndpoint

	bufPool sync.Pool
}

// New returns a Bind configured by opts.
func New(opts Options) (*Bind, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	b := &Bind{
		opts:    opts,
		path:    opts.Path,
		clients: make(map[string]*client),
		bufPool: sync.Pool{New: func() any {
			// One spare byte lets readMessage detect EOF on a maximum-size message.
			buf := make([]byte, maxPacketSize+1)
			return &buf
		}},
	}
	if b.path == "" {
		b.path = "/"
	}
	b.upgrader = websocket.Upgrader{
		ReadBufferSize:  bufferSize,
		WriteBufferSize: bufferSize,
		WriteBufferPool: &sync.Pool{},
		// Clients are not browsers, and the WireGuard handshake authenticates them.
		CheckOrigin: func(*http.Request) bool { return true },
	}
	if opts.Mode == ModeClient && opts.URL != "" {
		c, err := b.clientFor(opts.URL)
		if err != nil {
			return nil, err
		}
		b.defaultE = c.ep
	}
	return b, nil
}

func (b *Bind) verbosef(format string, args ...any) {
	if b.opts.Verbosef != nil {
		b.opts.Verbosef("WebSocket: "+format, args...)
	}
}

func (b *Bind) errorf(format string, args ...any) {
	if b.opts.Errorf != nil {
		b.opts.Errorf("WebSocket: "+format, args...)
	}
}

// Mode reports whether b is a server or a client.
func (b *Bind) Mode() Mode { return b.opts.Mode }

// Open puts the Bind into an open state. In server mode it starts listening,
// on the given port unless the listen address names one, and reports the bound
// port. In client mode nothing listens and the reported port is zero.
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.session != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	s := newSession()
	var actualPort uint16
	if b.opts.Mode == ModeServer {
		var err error
		actualPort, err = b.listenLocked(s, port)
		if err != nil {
			return nil, 0, err
		}
	} else if port != 0 {
		b.verbosef("Ignoring listen port %d in client mode", port)
	}
	b.session = s
	return []conn.ReceiveFunc{b.makeReceiveWebSocket(s)}, actualPort, nil
}

// Close closes the listener, if any, and every WebSocket connection.
func (b *Bind) Close() error {
	b.mu.Lock()
	s := b.session
	srv := b.server
	b.session, b.server, b.listener = nil, nil, nil
	b.mu.Unlock()

	if s == nil {
		return nil
	}
	var err error
	if srv != nil {
		// This closes the listener but not the hijacked WebSocket
		// connections, which the session closes below.
		err = srv.Close()
	}
	s.close()
	return err
}

// SetMark sets the mark on the listener and on every connection, and on any
// connection dialed later. This keeps the tunnel's own traffic out of the
// tunnel when policy routing is used, as wg-quick does for a default route.
func (b *Bind) SetMark(mark uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.mark = mark
	var err error
	if b.listener != nil {
		err = setMark(b.listener, mark)
	}
	if b.session != nil {
		for _, c := range b.session.snapshot() {
			if e := setMark(c.raw, mark); e != nil {
				// The connection may route through the tunnel; drop it so
				// that it is redialed with the mark.
				c.close()
			}
		}
	}
	return err
}

func (b *Bind) currentMark() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.mark
}

// BatchSize is the number of packets handled per receive and send.
func (b *Bind) BatchSize() int { return conn.IdealBatchSize }

// ParseEndpoint creates an endpoint from a UAPI endpoint string.
//
// In client mode, s may be a ws:// or wss:// URL, or a host:port, which is
// mapped to the configured server URL or, without one, to ws://host:port/path.
//
// In server mode, a host:port is accepted so that saved configurations keep
// loading, but the server never connects to it: the peer becomes reachable
// once it connects to the server.
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if b.opts.Mode == ModeServer {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		b.verbosef("Server mode does not connect to peers; endpoint %s is used only once the peer connects", s)
		return &ServerEndpoint{addr: ap}, nil
	}

	if isWSURL(s) {
		c, err := b.clientFor(s)
		if err != nil {
			return nil, err
		}
		return c.ep, nil
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		return nil, err
	}
	if b.defaultE != nil {
		b.verbosef("Using %s for endpoint %s", b.defaultE.c.display, s)
		return b.defaultE, nil
	}
	c, err := b.clientFor((&url.URL{Scheme: "ws", Host: s, Path: b.path}).String())
	if err != nil {
		return nil, err
	}
	return c.ep, nil
}

// DefaultEndpoint returns the endpoint of the configured server URL in client
// mode, which peers without an endpoint use.
func (b *Bind) DefaultEndpoint() conn.Endpoint {
	if b.defaultE == nil {
		return nil // not a nil *ClientEndpoint, which would be a non-nil interface
	}
	return b.defaultE
}

// Send writes each packet in bufs as a binary WebSocket message to the
// connection behind ep. If no connection is available the packets are
// dropped, as they would be on a lossy network, and a client starts dialing.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	s := b.session
	b.mu.Unlock()
	if s == nil {
		return net.ErrClosed
	}

	switch e := ep.(type) {
	case *ServerEndpoint:
		if b.opts.Mode != ModeServer {
			return conn.ErrWrongEndpointType
		}
		if e.conn == nil {
			return errNotConnected
		}
		if err := e.conn.write(bufs); err != nil {
			b.verbosef("Failed to send to %s: %v", e.addr, err)
		}
		return nil
	case *ClientEndpoint:
		if b.opts.Mode != ModeClient {
			return conn.ErrWrongEndpointType
		}
		e.c.send(s, bufs)
		return nil
	}
	return conn.ErrWrongEndpointType
}

// A session holds the state of one Open/Close cycle.
type session struct {
	rx   chan packet
	done chan struct{} // closed by close

	mu     sync.Mutex
	closed bool
	conns  map[*wsConn]struct{}
}

type packet struct {
	buf *[]byte
	n   int
	ep  conn.Endpoint
}

func newSession() *session {
	return &session{
		rx:    make(chan packet, rxQueueSize),
		done:  make(chan struct{}),
		conns: make(map[*wsConn]struct{}),
	}
}

// add registers c to be closed with the session. It reports false, without
// registering c, if the session is already closed.
func (s *session) add(c *wsConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *session) remove(c *wsConn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *session) snapshot() []*wsConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	conns := make([]*wsConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	return conns
}

func (s *session) isClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.done)
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()

	// Each close may wait briefly to send a close frame, so close them
	// concurrently to keep Close fast with many stalled connections.
	var wg sync.WaitGroup
	for c := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.close()
		}()
	}
	wg.Wait()
}

func (b *Bind) makeReceiveWebSocket(s *session) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		var p packet
		select {
		case p = <-s.rx:
		case <-s.done:
			return 0, net.ErrClosed
		}
		n := 0
		for {
			sizes[n] = copy(bufs[n], (*p.buf)[:p.n])
			eps[n] = p.ep
			b.bufPool.Put(p.buf)
			n++
			if n == len(bufs) {
				return n, nil
			}
			select {
			case p = <-s.rx:
			default:
				return n, nil
			}
		}
	}
}

// readLoop delivers the binary messages arriving on c to the session as
// packets from ep, until c fails or the session closes.
func (b *Bind) readLoop(s *session, c *wsConn, ep conn.Endpoint, timeout time.Duration) error {
	defer c.close()
	c.ws.SetReadLimit(maxPacketSize)
	for {
		c.ws.SetReadDeadline(time.Now().Add(timeout))
		typ, r, err := c.ws.NextReader()
		if err != nil {
			return err
		}
		if typ != websocket.BinaryMessage {
			continue
		}
		buf := b.bufPool.Get().(*[]byte)
		n, err := readMessage(r, *buf)
		if err != nil {
			b.bufPool.Put(buf)
			return err
		}
		if n == 0 {
			b.bufPool.Put(buf)
			continue
		}
		select {
		case s.rx <- packet{buf: buf, n: n, ep: ep}:
		case <-s.done:
			b.bufPool.Put(buf)
			return net.ErrClosed
		case <-c.done:
			b.bufPool.Put(buf)
			return net.ErrClosed
		}
	}
}

// readMessage reads the rest of a message into buf, which must be longer than
// the connection's read limit.
func readMessage(r io.Reader, buf []byte) (int, error) {
	n := 0
	for {
		if n == len(buf) {
			return n, errTooLarge
		}
		m, err := r.Read(buf[n:])
		n += m
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

// wsConn is a WebSocket connection that is safe for concurrent writers.
type wsConn struct {
	ws   *websocket.Conn
	raw  net.Conn // underlying TCP connection, for SetMark
	done chan struct{}

	writeMu   sync.Mutex
	closeOnce sync.Once
}

func newWSConn(ws *websocket.Conn, raw net.Conn) *wsConn {
	return &wsConn{ws: ws, raw: raw, done: make(chan struct{})}
}

func (c *wsConn) isClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *wsConn) write(bufs [][]byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeLocked(bufs)
}

// writeLocked writes bufs as binary messages. The caller must hold writeMu.
// A failed write leaves the connection unusable, so it is closed.
func (c *wsConn) writeLocked(bufs [][]byte) error {
	if c.isClosed() {
		return net.ErrClosed
	}
	c.ws.SetWriteDeadline(time.Now().Add(writeTimeout))
	for _, buf := range bufs {
		if err := c.ws.WriteMessage(websocket.BinaryMessage, buf); err != nil {
			c.close()
			return err
		}
	}
	return nil
}

// close sends a close frame, if it can do so promptly, and closes the connection.
func (c *wsConn) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		msg := websocket.FormatCloseMessage(websocket.CloseGoingAway, "")
		c.ws.WriteControl(websocket.CloseMessage, msg, time.Now().Add(250*time.Millisecond))
		c.ws.Close()
	})
}

// isExpectedClose reports whether err is the normal end of a connection.
func isExpectedClose(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) ||
		websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway)
}
