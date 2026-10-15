/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 christarcher. All Rights Reserved.
 */

package device

import (
	"fmt"
	"sync/atomic"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// countingBind counts how often the device opens its bind.
type countingBind struct {
	conn.Bind
	opens atomic.Int32
}

func (b *countingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.opens.Add(1)
	return b.Bind.Open(port)
}

// TestListenPortUnchanged checks that setting the current listen port again,
// as wg setconf and syncconf do, does not rebind.
func TestListenPortUnchanged(t *testing.T) {
	goroutineLeakCheck(t)
	bind := &countingBind{Bind: bindtest.NewChannelBinds()[0]}
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), bind, NewLogger(LogLevelError, ""))
	defer dev.Close()
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	if n := bind.opens.Load(); n != 1 {
		t.Fatalf("bind opened %d times by Up", n)
	}

	dev.net.Lock()
	port := dev.net.port
	dev.net.Unlock()
	if err := dev.IpcSet(fmt.Sprintf("listen_port=%d\n", port)); err != nil {
		t.Fatal(err)
	}
	if n := bind.opens.Load(); n != 1 {
		t.Errorf("setting the unchanged listen port rebound; bind opened %d times", n)
	}

	if err := dev.IpcSet(fmt.Sprintf("listen_port=%d\n", port+100)); err != nil {
		t.Fatal(err)
	}
	if n := bind.opens.Load(); n != 2 {
		t.Errorf("changing the listen port did not rebind; bind opened %d times", n)
	}
}
