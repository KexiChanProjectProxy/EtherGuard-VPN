// +build !linux,!openbsd,!freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package conn

import "net"

func (bind *StdNetBind) SetMark(mark uint32) error {
	return nil
}

// SetUDPConnMark is a no-op where sockets have no fwmark.
func SetUDPConnMark(*net.UDPConn, uint32) error {
	return nil
}
