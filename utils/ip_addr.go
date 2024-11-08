package utils

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"strings"

	"github.com/vishvananda/netlink"
)

// Equivalent to `ip addr add $ipString dev $linkName`
func IpAddrAdd(linkName string, ipString string) error {
	var (
		err  error
		l    netlink.Link
		addr *netlink.Addr
	)

	if linkName == "" || ipString == "" {
		return errors.New("link name or address can not be empty")
	}
	if l, err = netlink.LinkByName(linkName); err != nil {
		log.Debugf("IpAddrAdd unknow linkeName %s", linkName)
		return err
	}

	if addr, err = netlink.ParseAddr(ipString); err != nil {
		log.Debugf("IpAddrAdd error ip %s", ipString)
		return err
	}

	if err = netlink.AddrAdd(l, addr); err != nil {
		log.Debugf("IpAddrAdd error %v", err)
		if ok, _ := IpAddrIsExist(linkName, ipString); ok {
			log.Debugf("add existed %v", ipString)
			return nil
		}
	}

	/*
		bash := Bash{
			Command: fmt.Sprintf("ip addr show dev %s", linkName),
			Sudo:    true,
		}
		err = bash.Run()*/

	return nil
}

// Equivalent to `ip addr del $ipString dev $linkName`
func IpAddrDel(linkName string, ipString string) error {
	var (
		err  error
		l    netlink.Link
		addr *netlink.Addr
	)

	if linkName == "" || ipString == "" {
		return errors.New("link name or address can not be empty")
	}

	if l, err = netlink.LinkByName(linkName); err != nil {
		return err
	}

	if addr, err = netlink.ParseAddr(ipString); err != nil {
		return err
	}

	if err = netlink.AddrDel(l, addr); err != nil {
		if ok, err2 := IpAddrIsExist(linkName, ipString); !ok && err2 == nil {
			return nil
		}
	}

	return err
}

// Equivalent to `ip -4 a show $linkName`
func Ip4AddrShow(linkName string) ([]string, error) {

	return ipGetAddrList(linkName, FAMILY_V4)
}

// Equivalent to `ip -6 a show $linkName`
func Ip6AddrShow(linkName string) ([]string, error) {
	return ipGetAddrList(linkName, FAMILY_V6)
}

// Equivalent to `ip a show $linkName`
func IpAddrShow(linkName string) ([]string, error) {
	return ipGetAddrList(linkName, FAMILY_ALL)
}

// Equivalent to `ip -4 a flush $linkName`
func Ip4AddrFlush(linkName string) error {
	addr_list, err := Ip4AddrShow(linkName)
	if err != nil {
		return err
	}

	return ipDelAddrList(linkName, addr_list)
}

// Equivalent to `ip -6 a flush $linkName`
func Ip6AddrFlush(linkName string) error {
	addr_list, err := Ip6AddrShow(linkName)
	if err != nil {
		return err
	}

	return ipDelAddrList(linkName, addr_list)
}

// Equivalent to `ip a flush $linkName`
func IpAddrFlush(linkName string) error {
	addr_list, err := IpAddrShow(linkName)
	if err != nil {
		return err
	}

	return ipDelAddrList(linkName, addr_list)
}

func IpAddrIsExist(linkName string, ipString string) (bool, error) {
	if linkName == "" || ipString == "" {
		return false, errors.New("linkName or address can not be empty")
	}

	addr_list, err := IpAddrShow(linkName)
	if err != nil {
		return false, err
	}
	log.Debugf("%s address list: %v", linkName, addr_list)
	if len(addr_list) > 0 {
		for _, addr := range addr_list {
			if addr == ipString {
				return true, nil
			}
		}
	}

	return false, nil
}

func ipDelAddrList(linkName string, addr_list []string) error {
	if linkName == "" {
		return errors.New("linkname can not be empty")
	}
	if len(addr_list) == 0 {
		return nil
	}

	for _, addr := range addr_list {
		if strings.HasPrefix(addr, "fe80") {
			continue
		}
		if err := IpAddrDel(linkName, addr); err != nil {
			return err
		}
	}

	return nil
}

func ipGetAddrList(linkName string, family int) ([]string, error) {
	if linkName == "" {
		return nil, errors.New("linkName can not be empty")
	}

	addr_arry := make([]string, 0)
	l, err := netlink.LinkByName(linkName)
	if err != nil {
		return nil, err
	}

	addr_list, err := netlink.AddrList(l, family)
	if err != nil {
		return nil, err
	}

	if len(addr_list) > 0 {
		for _, addr := range addr_list {
			addr_arry = append(addr_arry, addr.IPNet.String())
		}
	}

	return addr_arry, nil
}
