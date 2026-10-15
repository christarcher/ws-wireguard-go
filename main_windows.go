/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/conn/wsbind"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] INTERFACE-NAME\n%s", os.Args[0], transportUsage)
	}
	transportOptions := transportFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(ExitSetupFailed)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(ExitSetupFailed)
	}
	interfaceName := fs.Arg(0)
	bindOptions, err := transportOptions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid transport options: %v\n", err)
		os.Exit(ExitSetupFailed)
	}

	fmt.Fprintln(os.Stderr, "Warning: this is a test program for Windows, mainly used for debugging this Go package.")

	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	logger.Verbosef("Starting ws-wireguard-go version %s", Version)

	tun, err := tun.CreateTUN(interfaceName, 0)
	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	} else {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	bindOptions.Verbosef = logger.Verbosef
	bindOptions.Errorf = logger.Errorf
	bind, err := wsbind.New(bindOptions)
	if err != nil {
		logger.Errorf("Failed to create WebSocket bind: %v", err)
		os.Exit(ExitSetupFailed)
	}

	device := device.NewDevice(tun, bind, logger)
	err = device.Up()
	if err != nil {
		logger.Errorf("Failed to bring up device: %v", err)
		os.Exit(ExitSetupFailed)
	}
	logger.Verbosef("Device started")

	uapi, err := ipc.UAPIListen(interfaceName)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		os.Exit(ExitSetupFailed)
	}

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()
	logger.Verbosef("UAPI listener started")

	// wait for program to terminate

	signal.Notify(term, os.Interrupt)
	signal.Notify(term, os.Kill)
	signal.Notify(term, windows.SIGTERM)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Verbosef("Shutting down")
}
