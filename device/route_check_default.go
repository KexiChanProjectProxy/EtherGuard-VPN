//go:build !linux

package device

import "github.com/KusakabeSi/EtherGuard-VPN/conn"

// platformRouteChecker is unavailable off Linux; every leg stays eligible.
func (device *Device) platformRouteChecker(conn.Bind) routeChecker {
	return nil
}
