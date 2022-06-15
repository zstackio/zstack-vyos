package utils

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

const (
	RT_PROTOS_ALL = -1
)

type IpRouteEntry struct {
	DevName string
	Dst     string
	Src     string
	GateWay string
	Scope   uint8
	Proto   int
	Metric  int
	Table   int
	Tos     int
	Type    int
}

func NewIpRoute() *IpRouteEntry {
	routeEntry := &IpRouteEntry{
		DevName: "",
		Dst:     "",
		Src:     "",
		GateWay: "",
		Scope:   RT_SCOPES_GLOBAL,
		Proto:   RT_PROTOS_STATIC,
		Metric:  0,
		Table:   RT_TABLES_MAIN,
		Tos:     0,
		Type:    RT_TYPE_UNICAST,
	}
	return routeEntry
}

func (r *IpRouteEntry) SetDst(dst string) *IpRouteEntry {
	if dst != "" {
		if !strings.Contains(dst, "/") {
			if net.ParseIP(dst).To4() != nil {
				dst = fmt.Sprintf("%s/32", dst)
			} else {
				dst = fmt.Sprintf("%s/128", dst)
			}
		}
		r.Dst = dst
	}

	return r
}
func (r *IpRouteEntry) SetSrc(src string) *IpRouteEntry {
	if src != "" {
		r.Src = src
	}

	return r
}
func (r *IpRouteEntry) SetDev(devName string) *IpRouteEntry {
	if devName != "" {
		r.DevName = devName
	}

	return r
}
func (r *IpRouteEntry) SetGW(gateWay string) *IpRouteEntry {
	if gateWay != "" {
		r.GateWay = gateWay
	}

	return r
}
func (r *IpRouteEntry) SetScope(scope uint8) *IpRouteEntry {
	r.Scope = scope

	return r
}
func (r *IpRouteEntry) SetProto(proto int) *IpRouteEntry {
	r.Proto = proto

	return r
}
func (r *IpRouteEntry) SetMetric(metric int) *IpRouteEntry {
	r.Metric = metric

	return r
}
func (r *IpRouteEntry) SetTable(table int) *IpRouteEntry {
	r.Table = table

	return r
}
func (r *IpRouteEntry) SetTos(tos int) *IpRouteEntry {
	r.Tos = tos

	return r
}
func (r *IpRouteEntry) SetType(t int) *IpRouteEntry {
	r.Type = t

	return r
}

func convertNetlinkRoute(r *IpRouteEntry) (*netlink.Route, error) {
	if r == nil {
		return nil, errors.New("route entry can not be nil")
	}
	newEntry := &netlink.Route{}

	if r.DevName != "" {
		iface, err := net.InterfaceByName(r.DevName)
		if err != nil {
			return nil, err
		}
		newEntry.LinkIndex = iface.Index
	}

	if r.Dst != "" {

		ipNet, err := netlink.ParseIPNet(r.Dst)
		if err != nil {
			return nil, err
		}
		newEntry.Dst = ipNet
	}

	if r.Src != "" {
		newEntry.Src = net.ParseIP(r.Src)
	}

	if r.GateWay != "" {
		newEntry.Gw = net.ParseIP(r.GateWay)
	}

	newEntry.Scope = netlink.Scope(r.Scope)
	newEntry.Priority = r.Metric
	newEntry.Protocol = r.Proto
	newEntry.Table = r.Table
	newEntry.Tos = r.Tos
	newEntry.Type = r.Type

	return newEntry, nil
}

func convertUserRoute(nlRouteList []netlink.Route) ([]*IpRouteEntry, error) {
	ipRouteList := []*IpRouteEntry{}

	for _, r := range nlRouteList {
		routeEntry := NewIpRoute()
		if r.LinkIndex != 0 {
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				return ipRouteList, err
			}
			routeEntry.DevName = link.Attrs().Name
		} else {
			routeEntry.DevName = ""
		}

		if r.Dst != nil {
			routeEntry.Dst = r.Dst.String()
		}
		if r.Src != nil {
			routeEntry.Src = r.Src.String()
		}
		if r.Gw != nil {
			routeEntry.GateWay = r.Gw.String()
		}
		routeEntry.Scope = uint8(r.Scope)
		routeEntry.Proto = r.Protocol
		routeEntry.Metric = r.Priority
		routeEntry.Table = r.Table
		routeEntry.Tos = r.Tos
		routeEntry.Type = r.Type

		ipRouteList = append(ipRouteList, routeEntry)
	}

	return ipRouteList, nil
}
