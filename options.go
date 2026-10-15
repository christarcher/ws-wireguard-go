/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 christarcher. All Rights Reserved.
 */

package main

import (
	"errors"
	"flag"
	"os"
	"strconv"

	"golang.zx2c4.com/wireguard/conn/wsbind"
)

// Every transport flag defaults to an environment variable, so that the
// transport can be configured when started by wg-quick, which passes only the
// interface name.
const (
	ENV_WG_WS_MODE           = "WG_WS_MODE"
	ENV_WG_WS_LISTEN         = "WG_WS_LISTEN"
	ENV_WG_WS_PATH           = "WG_WS_PATH"
	ENV_WG_WS_TLS_CERT       = "WG_WS_TLS_CERT"
	ENV_WG_WS_TLS_KEY        = "WG_WS_TLS_KEY"
	ENV_WG_WS_REAL_IP_HEADER = "WG_WS_REAL_IP_HEADER"
	ENV_WG_WS_URL            = "WG_WS_URL"
	ENV_WG_WS_INSECURE       = "WG_WS_INSECURE"
)

const transportUsage = `
Transport options (each defaults to the environment variable in brackets):
  --mode server|client   [WG_WS_MODE] server only accepts WebSocket connections,
                         client only dials them; inferred from --url or --listen
Server:
  --listen HOST[:PORT]   [WG_WS_LISTEN] listen address; without a port, the
                         interface's listen-port is used (default all addresses)
  --path PATH            [WG_WS_PATH] WebSocket path (default /)
  --tls-cert FILE        [WG_WS_TLS_CERT] serve wss:// with this certificate
  --tls-key FILE         [WG_WS_TLS_KEY] and this key
  --real-ip-header NAME  [WG_WS_REAL_IP_HEADER] trust the client address in this
                         header from a reverse proxy, e.g. X-Forwarded-For
Client:
  --url URL              [WG_WS_URL] ws:// or wss:// server URL for all peers;
                         without it, a peer endpoint HOST:PORT means
                         ws://HOST:PORT/PATH
  --path PATH            [WG_WS_PATH] path used with HOST:PORT endpoints
  --insecure             [WG_WS_INSECURE=1] do not verify the server certificate
`

// transportFlags registers the transport flags on fs and returns a function
// that builds the transport options once fs has been parsed.
func transportFlags(fs *flag.FlagSet) func() (wsbind.Options, error) {
	insecure, _ := strconv.ParseBool(os.Getenv(ENV_WG_WS_INSECURE))
	var (
		mode         = fs.String("mode", os.Getenv(ENV_WG_WS_MODE), "")
		listen       = fs.String("listen", os.Getenv(ENV_WG_WS_LISTEN), "")
		path         = fs.String("path", os.Getenv(ENV_WG_WS_PATH), "")
		tlsCert      = fs.String("tls-cert", os.Getenv(ENV_WG_WS_TLS_CERT), "")
		tlsKey       = fs.String("tls-key", os.Getenv(ENV_WG_WS_TLS_KEY), "")
		realIPHeader = fs.String("real-ip-header", os.Getenv(ENV_WG_WS_REAL_IP_HEADER), "")
		serverURL    = fs.String("url", os.Getenv(ENV_WG_WS_URL), "")
		skipVerify   = fs.Bool("insecure", insecure, "")
	)
	return func() (wsbind.Options, error) {
		opts := wsbind.Options{
			Path:               *path,
			ListenAddr:         *listen,
			TLSCertFile:        *tlsCert,
			TLSKeyFile:         *tlsKey,
			RealIPHeader:       *realIPHeader,
			URL:                *serverURL,
			InsecureSkipVerify: *skipVerify,
		}
		switch {
		case *mode != "":
			m, err := wsbind.ParseMode(*mode)
			if err != nil {
				return opts, err
			}
			opts.Mode = m
		case opts.URL != "":
			opts.Mode = wsbind.ModeClient
		case opts.ListenAddr != "" || opts.TLSCertFile != "":
			opts.Mode = wsbind.ModeServer
		default:
			return opts, errors.New("transport mode not given; use --mode server or --mode client, or set " + ENV_WG_WS_MODE)
		}
		return opts, opts.Validate()
	}
}
