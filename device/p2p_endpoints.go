package device

import (
	"net"
	"net/netip"
	"sort"
	"strconv"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

type interfaceAddresses struct {
	name  string
	index int
	flags net.Flags
	addrs []net.Addr
}

// maxSTUNSources caps how many pinned uplink sources one STUN refresh probes.
const maxSTUNSources = 8

// stunSource is one local uplink (interface + source address) that STUN
// discovery and endpoint probing can pin datagrams to.
type stunSource struct {
	ip      netip.Addr
	ifindex int
	ifname  string
}

func (s stunSource) String() string {
	return s.ifname + "/" + s.ip.String() + "#" + strconv.Itoa(s.ifindex)
}

// eligibleInterfaceIPs returns the addresses of iface that may carry underlay
// traffic: the interface is up, not loopback, not the VPN tap; addresses are
// global unicast outside shared address space and in an enabled family.
func eligibleInterfaceIPs(iface interfaceAddresses, tapName string, enabledAf conn.EnabledAf) []net.IP {
	if iface.name == tapName || iface.flags&net.FlagUp == 0 || iface.flags&net.FlagLoopback != 0 {
		return nil
	}
	var result []net.IP
	for _, address := range iface.addrs {
		ip := interfaceAddressIP(address)
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() {
			continue
		}
		if sharedAddressSpaceIP(ip) {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			if !enabledAf.IPv4 {
				continue
			}
			ip = ip4
		} else if !enabledAf.IPv6 {
			continue
		}
		result = append(result, ip)
	}
	return result
}

func endpointURLsForInterfaces(interfaces []interfaceAddresses, tapName string, port int, enabledAf conn.EnabledAf) []string {
	if port <= 0 || port > 65535 {
		return nil
	}
	endpoints := make(map[string]struct{})
	for _, iface := range interfaces {
		for _, ip := range eligibleInterfaceIPs(iface, tapName, enabledAf) {
			endpoints[net.JoinHostPort(ip.String(), strconv.Itoa(port))] = struct{}{}
		}
	}
	result := make([]string, 0, len(endpoints))
	for endpoint := range endpoints {
		result = append(result, endpoint)
	}
	sort.Strings(result)
	return result
}

// stunSourcesForInterfaces picks at most one source address per (interface,
// family) so each uplink is probed once. Interfaces must also be running
// (carrier up). A specific listen address restricts its family to that
// address, since replies to other addresses never reach the socket.
func stunSourcesForInterfaces(interfaces []interfaceAddresses, tapName string, enabledAf conn.EnabledAf, listenV4, listenV6 netip.Addr, limit int) []stunSource {
	restrict4 := listenV4.IsValid() && !listenV4.IsUnspecified()
	restrict6 := listenV6.IsValid() && !listenV6.IsUnspecified()
	var sources []stunSource
	for _, iface := range interfaces {
		if iface.index <= 0 || iface.flags&net.FlagRunning == 0 {
			continue
		}
		var have4, have6 bool
		for _, ip := range eligibleInterfaceIPs(iface, tapName, enabledAf) {
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is4() {
				if have4 || (restrict4 && addr != listenV4.Unmap()) {
					continue
				}
				have4 = true
			} else {
				if have6 || (restrict6 && addr != listenV6) {
					continue
				}
				have6 = true
			}
			sources = append(sources, stunSource{ip: addr, ifindex: iface.index, ifname: iface.name})
		}
	}
	sort.SliceStable(sources, func(i, j int) bool {
		if sources[i].ifindex != sources[j].ifindex {
			return sources[i].ifindex < sources[j].ifindex
		}
		return sources[i].ip.Is4() && !sources[j].ip.Is4()
	})
	if limit > 0 && len(sources) > limit {
		sources = sources[:limit]
	}
	return sources
}

func interfaceAddressIP(address net.Addr) net.IP {
	switch address := address.(type) {
	case *net.IPNet:
		return address.IP
	case *net.IPAddr:
		return address.IP
	default:
		return nil
	}
}

func sharedAddressSpaceIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
}

func (device *Device) interfaceRecords() []interfaceAddresses {
	interfaces, err := net.Interfaces()
	if err != nil {
		if device.log != nil {
			device.log.Verbosef("Local interface discovery failed: error=%v", err)
		}
		return nil
	}
	records := make([]interfaceAddresses, 0, len(interfaces))
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			if device.log != nil {
				device.log.Verbosef("Local interface address discovery failed: interface=%s error=%v", iface.Name, err)
			}
			continue
		}
		records = append(records, interfaceAddresses{name: iface.Name, index: iface.Index, flags: iface.Flags, addrs: addresses})
	}
	return records
}

func (device *Device) localEndpointURLs(port int) []string {
	records := device.interfaceRecords()
	if records == nil {
		return nil
	}
	return device.filterEndpointURLs(endpointURLsForInterfaces(records, device.EdgeConfig.Interface.Name, port, device.enabledAf))
}

// stunSources lists the local uplinks that per-interface STUN discovery and
// endpoint probing pin datagrams to.
func (device *Device) stunSources() []stunSource {
	if device == nil {
		return nil
	}
	var tapName string
	var listenV4, listenV6 netip.Addr
	if device.EdgeConfig != nil {
		tapName = device.EdgeConfig.Interface.Name
		listenV4, _ = netip.ParseAddr(device.EdgeConfig.DisableAf.ListenIPv4)
		listenV6, _ = netip.ParseAddr(device.EdgeConfig.DisableAf.ListenIPv6)
	}
	sources := stunSourcesForInterfaces(device.interfaceRecords(), tapName, device.enabledAf, listenV4, listenV6, 0)
	if len(sources) > maxSTUNSources {
		if device.log != nil {
			device.log.Verbosef("STUN sources truncated: found=%d limit=%d", len(sources), maxSTUNSources)
		}
		sources = sources[:maxSTUNSources]
	}
	return sources
}

func (device *Device) p2pLocalEndpointURLs() []string {
	return device.localEndpointURLs(device.activeListenPort())
}

func (device *Device) spreadPeerAdvertisement(response mtypes.BoardcastPeerMsg) error {
	body, err := mtypes.GetByte(response)
	if err != nil {
		return err
	}
	buf := make([]byte, path.EgHeaderLen+len(body))
	header, err := path.NewEgHeader(buf[:path.EgHeaderLen], device.EdgeConfig.Interface.MTU)
	if err != nil {
		return err
	}
	header.SetDst(mtypes.NodeID_Spread)
	header.SetSrc(device.ID)
	copy(buf[path.EgHeaderLen:], body)
	device.SpreadPacket(make(map[mtypes.Vertex]bool), path.BroadcastPeer, device.EdgeConfig.DefaultTTL, buf, MessageTransportOffsetContent)
	return nil
}

func (device *Device) spreadLocalEndpoints(requestID uint32) {
	device.staticIdentity.RLock()
	publicKey := device.staticIdentity.publicKey
	device.staticIdentity.RUnlock()
	for _, endpoint := range device.p2pLocalEndpointURLs() {
		response := mtypes.BoardcastPeerMsg{
			Request_ID: requestID,
			NodeID:     device.ID,
			PubKey:     publicKey,
			ConnURL:    endpoint,
		}
		if err := device.spreadPeerAdvertisement(response); err != nil {
			device.log.Errorf("P2P self endpoint advertisement failed: endpoint=%s error=%v", endpoint, err)
			continue
		}
		device.log.Verbosef("P2P self endpoint advertised: endpoint=%s", endpoint)
	}
}
