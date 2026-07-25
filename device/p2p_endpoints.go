package device

import (
	"net"
	"sort"
	"strconv"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

type interfaceAddresses struct {
	name  string
	flags net.Flags
	addrs []net.Addr
}

func endpointURLsForInterfaces(interfaces []interfaceAddresses, tapName string, port int, enabledAf conn.EnabledAf) []string {
	if port <= 0 || port > 65535 {
		return nil
	}
	endpoints := make(map[string]struct{})
	for _, iface := range interfaces {
		if iface.name == tapName || iface.flags&net.FlagUp == 0 || iface.flags&net.FlagLoopback != 0 {
			continue
		}
		for _, address := range iface.addrs {
			ip := interfaceAddressIP(address)
			if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() {
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

func (device *Device) p2pLocalEndpointURLs() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		device.log.Verbosef("P2P local interface discovery failed: error=%v", err)
		return nil
	}
	records := make([]interfaceAddresses, 0, len(interfaces))
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			device.log.Verbosef("P2P local interface address discovery failed: interface=%s error=%v", iface.Name, err)
			continue
		}
		records = append(records, interfaceAddresses{name: iface.Name, flags: iface.Flags, addrs: addresses})
	}
	return endpointURLsForInterfaces(records, device.EdgeConfig.Interface.Name, device.activeListenPort(), device.enabledAf)
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
