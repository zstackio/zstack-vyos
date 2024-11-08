package utils

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ip_route_test", func() {
	var link = "eth2"
	It("test ip-route prep env", func() {
		err := Ip4AddrFlush(link)
		Expect(err).To(BeNil(), fmt.Sprintf("ip addr flush error: %s", err))
		err = IpAddrAdd(link, "10.10.10.10/24")
		Expect(err).To(BeNil(), fmt.Sprintf("ip addr add error: %s", err))

		err = Ip6AddrFlush(link)
		Expect(err).To(BeNil(), fmt.Sprintf("ip addr6 flush error: %s", err))
		err = IpAddrAdd(link, "2001::1002/64")
		Expect(err).To(BeNil(), fmt.Sprintf("ip addr6 add error: %s", err))

		_ = IpLinkSetUp(link)
	})
	It("test ip-route ipv4", func() {
		routeEntry := NewIpRoute().SetDst("10.10.10.120").SetGW("10.10.10.1").SetSrc("10.10.10.10").SetDev(link).SetMetric(161).SetProto(RT_PROTOS_STATIC)
		Expect(routeEntry).NotTo(BeNil(), "set route entry error")
		err := IpRouteAdd(routeEntry)
		Expect(err).To(BeNil(), fmt.Sprintf("ip route add error: %s", err))

		isExist := IpRouteIsExist(routeEntry)
		Expect(isExist).To(BeTrue(), "route should exist")

		err = IpRouteDel(routeEntry)
		Expect(err).To(BeNil(), fmt.Sprintf("ip route del error: %s", err))

		isExist = IpRouteIsExist(routeEntry)
		Expect(isExist).NotTo(BeTrue(), "route entry should not exist")

	})
	It("test ip-route ipv6", func() {
		routeEntry := NewIpRoute().SetDst("2001::/64").SetGW("2001::1").SetDev(link).SetMetric(156)
		Expect(routeEntry).NotTo(BeNil(), "set route6 entry error")

		IpRouteDel(routeEntry) //ipv6 can not auto flush
		err := IpRouteAdd(routeEntry)
		Expect(err).To(BeNil(), fmt.Sprintf("ip route6 add error: %s", err))

		fmt.Println(routeEntry)
		testEntry, _ := Ip6RouteShow(link)
		for _, r := range testEntry {
			fmt.Println(r)
		}

		isExist := IpRouteIsExist(routeEntry)
		Expect(isExist).To(BeTrue(), "route6 should exist")

		err = IpRouteDel(routeEntry)
		Expect(err).To(BeNil(), fmt.Sprintf("ip route6 del error: %s", err))
		isExist = IpRouteIsExist(routeEntry)
		Expect(isExist).NotTo(BeTrue(), "route6 entry should not exist")
	})

	It("test ip-route add/del blackhole", func() {
		rtEntry1 := NewIpRoute().SetDst("10.20.20.20").SetType(RT_TYPE_BLACKHOLE)
		err := IpRouteAdd(rtEntry1)
		Expect(err).To(BeNil(), fmt.Sprintf("ip route add blackhole 10.20.20.20 error: %s", err))
		isExist := IpRouteIsExist(rtEntry1)
		Expect(isExist).To(BeTrue(), "route should exist")

		rtEntry2 := NewIpRoute().SetDst("10.30.30.30").SetType(RT_TYPE_BLACKHOLE).SetMetric(171)
		err = IpRouteAdd(rtEntry2)
		Expect(err).To(BeNil(), fmt.Sprintf("ip route add blackhole 10.30.30.30 metric 171 error: %s", err))
		isExist = IpRouteIsExist(rtEntry2)
		Expect(isExist).To(BeTrue(), "route should exist")

		err = IpRouteDel(rtEntry1)
		Expect(err).To(BeNil(), fmt.Sprintf("ip route del error: %s", err))
		err = IpRouteDel(rtEntry2)
		Expect(err).To(BeNil(), fmt.Sprintf("ip route del error: %s", err))
		isExist = IpRouteIsExist(rtEntry1)
		Expect(isExist).To(BeFalse(), "route should not exist")
		isExist = IpRouteIsExist(rtEntry2)
		Expect(isExist).To(BeFalse(), "route should not exist")
	})

	It("test ip-route get route", func() {
		rtEnrty := NewIpRoute().SetDst("10.20.20.0/24").SetGW("10.10.10.254")
		err := IpRouteAdd(rtEnrty)
		Expect(err).To(BeNil(), "IpRouteAdd error: %+v", err)
		ipString, err := IpRouteGet("10.20.20.30")
		Expect(err).To(BeNil(), "ip route get error: %+v", err)
		Expect(ipString).To(Equal("10.10.10.254"), "ip route get error")
		fmt.Printf("ipString: %+v\n", ipString)
	})

	It("test ip-route clean env", func() {
		err := IpAddrDel(link, "10.10.10.10/24")
		Expect(err).To(BeNil(), fmt.Sprintf("ip addr del error: %s", err))
		err = IpAddrDel(link, "2001::1002/64")
		Expect(err).To(BeNil(), fmt.Sprintf("ip addr6 del error: %s", err))
	})

})
