package utils

import (
	"errors"
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type IplInkType int
const (
	IpLinkTypeIfb IplInkType = iota + 1
	IpLinkTypeIfbBridge
	IpLinkTypeMacVtap
	IpLinkTypeVeth
)

func (linkType IplInkType) String() string {
	switch linkType {
	case IpLinkTypeIfb:
		return "ifb"
	case IpLinkTypeIfbBridge:
		return "bridge"
	case IpLinkTypeMacVtap:
		return "macvtap"
	case IpLinkTypeVeth:
		return "veth"
	default:
		return "Unknown"	
	}
}

const (
	MGMT_VRF 	= "mgmt"
)

type IpLinkAttrs struct {
	LinkName    string
	LinkIndex   int
	Alias       string
	Type        string
	State       string
	MTU         int
	MAC         string
	Promisc     int
	TxQueueLen  int
	NumTxQueues int
	NumRxQueues int
}

// Equivalent to `ip link add $linkName type $linkType`
func IpLinkAdd(linkName string, linkType string) error {
	var err error
	if linkName == "" || linkType == "" {
		return errors.New("link name or type can not be empty")
	}
	linkAttr := netlink.NewLinkAttrs()
	switch linkType {
		case IpLinkTypeIfbBridge.String(): {
			linkAttr.Name = linkName
			bridge := &netlink.Bridge{LinkAttrs: linkAttr}
			if err = netlink.LinkAdd(bridge); err != nil {
				if IpLinkIsExist(linkName) {
					return nil
				}
			}
	
			return err
		} 

		case IpLinkTypeIfb.String(): {
			linkAttr.Name = linkName
			ifb := &netlink.Ifb{LinkAttrs: linkAttr}
			if err = netlink.LinkAdd(ifb); err != nil {
				if IpLinkIsExist(linkName) {
					return nil
				}
			}

			return err
		}

	case IpLinkTypeMacVtap.String(): {
		var linkMap map[string]Nic
		if linkMap, err = GetAllNics(); err != nil {
			log.Debugf("failed to get all links: %v", err)
			return err
		} 

		var linkNames  []string
		for _, l := range linkMap {
			linkNames = append(linkNames, l.Name)
		}

		parentLink := ""
		for _, link := range linkNames {
			log.Debugf("link name: %s", link)
			if strings.Contains(link, "eth") ||  strings.Contains(link, "ens"){
				parentLink = link
				break
			}
		}
		if parentLink == "" {
			log.Debugf("can not find link name start with: eth or ens:")
			return fmt.Errorf("can not find link name start with: eth or ens:")
		}
		
		pl, _  := netlink.LinkByName(parentLink)
		macvtap := &netlink.Macvtap {
			Macvlan: netlink.Macvlan{
				LinkAttrs: netlink.LinkAttrs{
					Name: linkName,
					ParentIndex: pl.Attrs().Index,
				},
				Mode: netlink.MACVLAN_MODE_BRIDGE,
			},
		}

		if err := netlink.LinkAdd(macvtap); err != nil {
			log.Debugf("Failed to add macvtap device: %v", err)
			if !strings.Contains(err.Error(), "file exists") {
				return err
			}
		}
		
		if err := netlink.LinkSetUp(macvtap); err != nil {
			log.Debugf("Failed to set macvtap device up: %v", err)
			return err
		}

		return nil
	}

	case IpLinkTypeVeth.String(): {
		peerName := linkName + "-peer"
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: linkName,
			},
			PeerName: peerName,
		}
		
		if _, err = netlink.LinkByName(linkName); err == nil {
			IpLinkDel(linkName)
		}

		if _, err = netlink.LinkByName(peerName); err == nil {
			IpLinkDel(peerName)
		}
		
		if err := netlink.LinkAdd(veth); err != nil {
			log.Debugf("Failed to add veth pair: %v", err)
			return err
		}
		
		if err := netlink.LinkSetUp(veth); err != nil {
			log.Debugf("Failed to up veth pair: %v", err)
			return err
		}
		
		if err := IpLinkSetUp(peerName); err != nil {
			log.Debugf("Failed to up veth pair: %v", err)
			return err
		}
		
		return nil
	}
		
	default:
		return errors.New("type is not support")
	}
}

// Equivalent to `ip link del $linkName`
func IpLinkDel(linkName string) error {
	var (
		err error
		l   netlink.Link
	)
	if linkName == "" {
		return errors.New("link name can not be empty")
	}
	if l, err = netlink.LinkByName(linkName); err != nil {
		return err
	}

	if err = netlink.LinkDel(l); err != nil {
		if !IpLinkIsExist(linkName) {
			return nil
		}
	}

	return err
}

// Equivalent to `ip link set $linkName up`
func IpLinkSetUp(linkName string) error {
	if linkName == "" {
		return errors.New("link name can not be empty")
	}
	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}

	return netlink.LinkSetUp(l)
}

// Equivalent to `ip link set $linkName down`
func IpLinkSetDown(linkName string) error {
	if linkName == "" {
		return errors.New("link name can not be empty")
	}
	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}

	return netlink.LinkSetDown(l)
}

// Equivalent to `ip link set $linkName address $macAddr`
func IpLinkSetMAC(linkName string, macAddr string) error {
	if linkName == "" || macAddr == "" {
		return errors.New("link name or mac address can not be empty")
	}
	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}

	hardAddr, err := net.ParseMAC(macAddr)
	if err != nil {
		return err
	}

	return netlink.LinkSetHardwareAddr(l, hardAddr)
}

func IpLinkGetMAC(linkName string) (string, error) {
	if linkName == "" {
		return "", errors.New("link name can not be empty")
	}
	iface, err := net.InterfaceByName(linkName)
	if err != nil {
		return "", err
	}

	return iface.HardwareAddr.String(), nil
}

// Equivalent to `ip link set $linkName mtu $mtu`
func IpLinkSetMTU(linkName string, mtu int) error {
	if linkName == "" || mtu <= 0 {
		return errors.New("link name or mtu can not be empty")
	}
	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}

	return netlink.LinkSetMTU(l, mtu)
}

func IpLinkGetMTU(linkName string) (int, error) {
	if linkName == "" {
		return 0, errors.New("link name can not be empty")
	}
	iface, err := net.InterfaceByName(linkName)
	if err != nil {
		return 0, err
	}

	return iface.MTU, nil
}

// Equivalent to `ip link set $linkName name $newName`
func IpLinkSetName(linkName string, newName string) error {
	if linkName == "" || newName == "" {
		return errors.New("link name or new name can not be empty")
	}
	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}

	return netlink.LinkSetName(l, newName)
}

// Equivalent to `ip link set $linkName alias $alias`
func IpLinkSetAlias(linkName string, alias string) error {
	if linkName == "" {
		return errors.New("link name can not be empty")
	}
	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}

	return netlink.LinkSetAlias(l, alias)
}

// Equivalent to `ip link set $linkName promisc $flag`
func IpLinkSetPromisc(linkName string, flag bool) error {
	if linkName == "" {
		return errors.New("link name can not be empty")
	}
	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}

	if flag {
		return netlink.SetPromiscOn(l)
	}

	return netlink.SetPromiscOff(l)
}

// Equivalent to `ip -d link show $linkName`
func IpLinkShowAttrs(linkName string) (*IpLinkAttrs, error) {
	if linkName == "" {
		return nil, errors.New("link name can not be empty")
	}

	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return nil, err
	}

	linkAttr := IpLinkAttrs{}
	linkAttr.LinkName = linkName
	linkAttr.LinkIndex = l.Attrs().Index
	linkAttr.Alias = l.Attrs().Alias
	linkAttr.MAC = l.Attrs().HardwareAddr.String()
	linkAttr.MTU = l.Attrs().MTU
	linkAttr.Promisc = l.Attrs().Promisc
	linkAttr.TxQueueLen = l.Attrs().TxQLen
	linkAttr.NumRxQueues = l.Attrs().NumRxQueues
	linkAttr.NumTxQueues = l.Attrs().NumTxQueues
	linkAttr.State = l.Attrs().OperState.String()
	linkAttr.Type = l.Type()

	return &linkAttr, nil
}

// Equivalent to `ip link set $linkName txqlen $qlen`
func IpLinkSetTXQLen(linkName string, qlen int) error {
	if linkName == "" {
		return errors.New("link name can not be empty")
	}

	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}

	return netlink.LinkSetTxQLen(l, qlen)
}

func IpLinkIsUp(linkName string) (bool, error) {
	if linkName == "" {
		return false, errors.New("link name can not be empty")
	}

	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return false, err
	}
	if l.Attrs().OperState == IF_OPER_UP || l.Attrs().OperState == IF_OPER_UNKNOWN {
		return true, nil
	}

	return false, nil
}

func IpLinkIsExist(linkName string) bool {
	iface, err := net.InterfaceByName(linkName)
	if err != nil || iface.Name != linkName {
		return false
	}

	return true
}

func IpLinkSetMaster(linkName string, masterName string) error {
	if linkName == "" {
		return errors.New("link name can not be empty")
	}
	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}

	if masterName == "" {
		return netlink.LinkSetNoMaster(l)
	} else {
		master, err := netlink.LinkByName(masterName)
		if err != nil {
			return err
		}

		return netlink.LinkSetMaster(l, master)
	}
}