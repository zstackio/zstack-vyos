package utils

import (
	"errors"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

// Equivalent to `ip route add $IpRouteEntry`
func IpRouteAdd(r *IpRouteEntry) error {
	var (
		err          error
		netlinkRoute *netlink.Route
	)

	if netlinkRoute, err = convertNetlinkRoute(r); err != nil {
		return err
	}

	if err = netlink.RouteAdd(netlinkRoute); err != nil {
		if IpRouteIsExist(r) {
			return nil
		}
	}

	return err
}

// Equivalent to `ip route del $IpRouteEntry`
func IpRouteDel(r *IpRouteEntry) error {
	var (
		err          error
		netlinkRoute *netlink.Route
	)

	if netlinkRoute, err = convertNetlinkRoute(r); err != nil {
		return err
	}

	if err = netlink.RouteDel(netlinkRoute); err != nil {
		if !IpRouteIsExist(r) {
			return nil
		}
	}

	return err
}

// Equivalent to `ip route show dev $linkName`
func Ip4RouteShow(linkName string) ([]*IpRouteEntry, error) {
	return ipRouteShow(linkName, FAMILY_V4)
}

// Equivalent to `ip -6 route show dev $linkName`
func Ip6RouteShow(linkName string) ([]*IpRouteEntry, error) {
	return ipRouteShow(linkName, FAMILY_V6)
}

func IpRouteShow(linkName string) ([]*IpRouteEntry, error) {
	return ipRouteShow(linkName, FAMILY_ALL)
}

func IpRouteGet(address string) (string, error) {
	var routeList []netlink.Route
	var ipString net.IP
	var err error
	if address == "" {
		return "", errors.New("address is nil")
	}
	if strings.Contains(address, "/") {
		if ipString, _, err = net.ParseCIDR(address); err != nil || ipString == nil {
			return "", err
		}
	} else {
		ipString = net.ParseIP(address)
	}
	if routeList, err = netlink.RouteGet(ipString); err != nil || len(routeList) == 0 {
		return "", err
	}
	for _, r := range routeList {
		if r.Gw != nil {
			return r.Gw.String(), nil
		}
	}

	return "", errors.New("can not get route")
}

func IpRouteDelDefault(table int) error {
	return ipRouteDelDefault(table, netlink.FAMILY_ALL)
}

func Ip4RouteDelDefault(table int) error {
	return ipRouteDelDefault(table, netlink.FAMILY_V4)
}

func Ip6RouteDelDefault(table int) error {
	return ipRouteDelDefault(table, netlink.FAMILY_V6)
}

func IpRouteFilter(r *IpRouteEntry) ([]*IpRouteEntry, error) {
	var filterMask uint64
	rt_filter := &netlink.Route{}

	if r.DevName != "" {
		iface, err := net.InterfaceByName(r.DevName)
		if err != nil {
			return nil, err
		}
		rt_filter.LinkIndex = iface.Index
		filterMask |= netlink.RT_FILTER_OIF
	}
	if r.Dst != "" {
		ipNet, err := netlink.ParseIPNet(r.Dst)
		if err != nil {
			return nil, err
		}
		rt_filter.Dst = ipNet
		filterMask |= netlink.RT_FILTER_DST
	}
	if r.Src != "" {
		rt_filter.Src = net.ParseIP(r.Src)
		filterMask |= netlink.RT_FILTER_SRC
	}
	if r.GateWay != "" {
		rt_filter.Gw = net.ParseIP(r.GateWay)
		filterMask |= netlink.RT_FILTER_GW
	}
	if r.Scope != RT_SCOPES_GLOBAL {
		rt_filter.Scope = netlink.Scope(r.Scope)
		filterMask |= netlink.RT_FILTER_SCOPE
	}
	if r.Proto != RT_PROTOS_STATIC {
		rt_filter.Protocol = r.Proto
		filterMask |= netlink.RT_FILTER_PROTOCOL
	}
	if r.Table != RT_TABLES_MAIN {
		rt_filter.Table = r.Table
		filterMask |= netlink.RT_FILTER_TABLE
	}
	if r.Tos != 0 {
		rt_filter.Tos = r.Tos
		filterMask |= netlink.RT_FILTER_TOS
	}
	if r.Type != RT_TYPE_UNICAST {
		rt_filter.Type = r.Type
		filterMask |= netlink.RT_FILTER_TYPE
	}

	rtList, err := netlink.RouteListFiltered(FAMILY_ALL, rt_filter, filterMask)
	if err != nil || len(rtList) == 0 {
		return nil, err
	}

	return convertUserRoute(rtList)
}

func IpRouteIsExist(r *IpRouteEntry) bool {
	if routeList, err := IpRouteFilter(r); err != nil || len(routeList) == 0 {
		return false
	}

	return true
}

func ipRouteDelDefault(table int, family int) error {
	if table < 0 {
		return errors.New("route table can not be negative")
	}
	rt_filter := &netlink.Route{}
	rt_filter.Table = table
	rt_filter.Src = nil
	rt_filter.Dst = nil

	rList, err := netlink.RouteListFiltered(family, rt_filter, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_SRC|netlink.RT_FILTER_DST)
	if err != nil {
		return err
	}
	for _, r := range rList {
		if err := netlink.RouteDel(&r); err != nil {
			return err
		}
	}

	return nil
}

func ipRouteShow(linkName string, family int) ([]*IpRouteEntry, error) {
	var link netlink.Link
	var err error

	if linkName != "" {
		if link, err = netlink.LinkByName(linkName); err != nil {
			return nil, err
		}
	}

	nlRouteList, err := netlink.RouteList(link, family)
	if err != nil {
		return nil, err
	}

	return convertUserRoute(nlRouteList)
}
