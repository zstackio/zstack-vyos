package utils

import (
	"context"
	"fmt"
	"net"
	"sort"

	log "github.com/sirupsen/logrus"
)

var (
	MgtNicForUT            NicInfo
	PubNicForUT            NicInfo
	PriNicForUT            NicInfo
	PrivateNicsForUT       []NicInfo
	AdditionalPubNicsForUT []NicInfo
	reservedIpForMgt       []string
	reservedIpForPubL3     []string
	freeIpsForMgt          []string
	freeIpsForPubL3        []string
)

func parseNicForUT(m map[string]interface{}) (NicInfo, error) {
	nicInfo := NicInfo{}
	name, ok := m["deviceName"].(string)
	if !ok {
		return nicInfo, fmt.Errorf("there is no nic name for %+v", m)
	}
	nicInfo.Name = name

	mac, ok := m["mac"].(string)
	if !ok {
		return nicInfo, fmt.Errorf("there is no nic mac for %+v", m)
	}
	nicInfo.Mac = mac

	ip, ok := m["ip"].(string)
	if !ok {
		nicInfo.Ip = ""
	} else {
		nicInfo.Ip = ip
	}

	netmask, ok := m["netmask"].(string)
	if !ok {
		nicInfo.Netmask = ""
	} else {
		nicInfo.Netmask = netmask
	}

	gateway, ok := m["gateway"].(string)
	if !ok {
		nicInfo.Gateway = ""
	} else {
		nicInfo.Gateway = gateway
	}

	ip6, ok := m["ip6"].(string)
	if !ok {
		nicInfo.Ip6 = ""
	} else {
		nicInfo.Ip6 = ip6
	}

	prefixLength, ok := m["prefixLength"].(float64)
	if !ok {
		nicInfo.PrefixLength = 0
	} else {
		nicInfo.PrefixLength = int(prefixLength)
	}

	gateway6, ok := m["gateway6"].(string)
	if !ok {
		nicInfo.Gateway6 = ""
	} else {
		nicInfo.Gateway6 = gateway6
	}

	isDefault, ok := m["isDefaultRoute"].(bool)
	if !ok {
		nicInfo.IsDefault = false
	} else {
		nicInfo.IsDefault = isDefault
	}

	category, ok := m["category"].(string)
	if !ok {
		return nicInfo, fmt.Errorf("there is no nic category for %+v", m)
	}
	nicInfo.Category = category

	l2Type, ok := m["l2type"].(string)
	if !ok {
		nicInfo.L2Type = ""
	} else {
		nicInfo.L2Type = l2Type
	}

	physicalInterface, ok := m["physicalInterface"].(string)
	if !ok {
		nicInfo.PhysicalInterface = ""
	} else {
		nicInfo.PhysicalInterface = physicalInterface
	}

	vni, ok := m["vni"].(int)
	if !ok {
		nicInfo.Vni = 0
	} else {
		nicInfo.Vni = vni
	}

	mtu, ok := m["mtu"].(int)
	if !ok {
		nicInfo.Mtu = 1450
	} else {
		nicInfo.Mtu = mtu
	}

	addressMode, ok := m["addressMode"].(string)
	if !ok {
		nicInfo.AddressMode = "Stateful-DHCP"
	} else {
		nicInfo.AddressMode = addressMode
	}

	nicInfo.FirewallDefaultAction = "reject"

	return nicInfo, nil
}

func ParseBootStrapNicInfo() {
	PrivateNicsForUT = []NicInfo{}
	AdditionalPubNicsForUT = []NicInfo{}
	reservedIpForMgt = []string{}
	reservedIpForPubL3 = []string{}
	freeIpsForMgt = []string{}
	freeIpsForPubL3 = []string{}
	nicString := BootstrapInfo["managementNic"].(map[string]interface{})
	if nicString != nil {
		nicInfo, err := parseNicForUT(nicString)
		PanicOnError(err)
		MgtNicForUT = nicInfo
	}

	otherNics := BootstrapInfo["additionalNics"].([]interface{})
	if otherNics != nil {
		for _, o := range otherNics {
			onic := o.(map[string]interface{})
			nicInfo, err := parseNicForUT(onic)
			PanicOnError(err)

			if nicInfo.IsDefault {
				PubNicForUT = nicInfo
				continue
			}

			if nicInfo.Category == NIC_TYPE_PRIVATE {
				PrivateNicsForUT = append(PrivateNicsForUT, nicInfo)
			} else {
				AdditionalPubNicsForUT = append(AdditionalPubNicsForUT, nicInfo)
			}
		}
	}

	sort.Sort(NicArray(PrivateNicsForUT))
	sort.Sort(NicArray(AdditionalPubNicsForUT))

	ips := BootstrapInfo["reservedIpForMgt"].([]interface{})
	for _, ip := range ips {
		reservedIpForMgt = append(reservedIpForMgt, ip.(string))
	}

	ips = BootstrapInfo["reservedIpForPubL3"].([]interface{})
	for _, ip := range ips {
		reservedIpForPubL3 = append(reservedIpForPubL3, ip.(string))
	}
}

func SetEnableVyosCmdForUT(enable bool) {
	if enable {
		BootstrapInfo["EnableVyosCmd"] = true
	} else {
		BootstrapInfo["EnableVyosCmd"] = false
	}
}

func StartUdpServer(ip string, port int, ctx context.Context) error {
	addr := net.ParseIP(ip)
	if addr == nil {
		log.Debugf("failed to parse IP address: %s", ip)
		return fmt.Errorf("failed to parse IP address: %s", ip)
	}

	var conn *net.UDPConn
	var err error
	if addr.To4() == nil {
		udpAddr, err := net.ResolveUDPAddr("udp6", fmt.Sprintf("[%s]:%d", ip, port))
		if err != nil {
			log.Debugf("Error resolving address: %v", err)
			return fmt.Errorf("Error resolving address: %v", err)
		}

		conn, err = net.ListenUDP("udp6", udpAddr)
		if err != nil {
			log.Debugf("failed to listen on UDP: %v", err)
			return fmt.Errorf("failed to listen on UDP: %v", err)
		}
	} else {
		conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: addr, Port: port})
		if err != nil {
			log.Debugf("failed to listen on UDP: %v", err)
			return err
		}
	}
	defer conn.Close()

	log.Debugf("[udp server] started on %s:%d", ip, port)
	buffer := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			log.Debugf("server[%s:%d] done", ip, port)
			return nil
		default:
			_, remoteAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				log.Debugf("failed to read from UDP: %v", err)
				continue
			}

			_, err = conn.WriteToUDP(buffer[:4], remoteAddr)
			if err != nil {
				log.Debugf("failed to write to UDP: %v", err)
				continue
			}
		}
	}
}
