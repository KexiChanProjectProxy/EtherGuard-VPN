//go:build !linux

package device

import "github.com/KusakabeSi/EtherGuard-VPN/conn"

// platformRouteChecker is unavailable off Linux; every leg stays eligible.
func (device *Device) platformRouteChecker(conn.Bind) routeChecker {
	return nil
}

// CheckUplinkRoute keeps every uplink off Linux.
func CheckUplinkRoute(Uplink, uint32) error {
	return nil
}
