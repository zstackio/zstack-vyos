package plugin

import (
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("route_linux_test", func() {
	var (
		nextHopInPubL3                     string
		nextHopInmgt                       string
		r0, r1, r2, r3, r4, r5, r6, r7, r8 RouteInfo
		nicCmd                             *configureNicCmd
	)

	It("[REPLACE_VYOS]: pre test env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"route_linux_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetEnableVyosCmdForUT(false)
		utils.SetSkipVyosIptables(true)
		nextHopInPubL3, _ = utils.GetFreePubL3Ip()
		nextHopInmgt, _ = utils.GetFreeMgtIp()
		r0 = RouteInfo{Destination: "172.16.90.0/24", Target: utils.GetMgtGateway(), Distance: 1}
		r1 = RouteInfo{Destination: "1.1.1.0/24", Target: nextHopInPubL3, Distance: 100}
		r2 = RouteInfo{Destination: "1.1.2.0/24", Target: nextHopInPubL3, Distance: 110}
		r3 = RouteInfo{Destination: "1.1.3.0/24", Target: nextHopInmgt, Distance: 120}
		r4 = RouteInfo{Destination: "1.1.4.0/24", Target: nextHopInmgt, Distance: 130}
		r5 = RouteInfo{Destination: "1.1.5.0/24", Target: "", Distance: 80}
		r6 = RouteInfo{Destination: "1.1.6.0/24", Target: "", Distance: 90}
		r7 = RouteInfo{Destination: "7.7.7.0/24", Target: "7.7.7.7", Distance: 150}
		r8 = RouteInfo{Destination: "8.8.8.0/24", Target: "8.8.8.8", Distance: 151}

		nicCmd = &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)
	})

	It("[REPLACE_VYOS]: test add route", func() {
		routes := []RouteInfo{r0, r1, r2, r3, r4, r5, r6}
		SetZebraRoutes(routes)
		checkRoutesByLinux(routes, nil)
	})

	It("[REPLACE_VYOS]: test del route", func() {
		routes1 := []RouteInfo{r0, r5, r6}
		SetZebraRoutes(routes1)
		deleteRoutes := []RouteInfo{r1, r2, r3, r4}
		checkRoutesByLinux(routes1, deleteRoutes)
		SetZebraRoutes([]RouteInfo{})
		checkRoutesByLinux(nil, routes1)
	})

	It("[REPLACE_VYOS]: test add unreachable route", func() {
		routes1 := []RouteInfo{r1, r2, r3, r4, r5, r6}
		SetZebraRoutes(routes1)
		checkRoutesByLinux(routes1, []RouteInfo{})
		routes2 := []RouteInfo{r7, r2, r3, r8, r5, r6, r1, r4}
		SetZebraRoutes(routes2)
		checkRoutesByLinux(routes2, []RouteInfo{})
	})

	It("[REPLACE_VYOS]: clean test env", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkRoutesByLinux(routes []RouteInfo, routesDeleted []RouteInfo) {
	jsonRoutes := []*utils.ZebraRoute{}
	err := utils.JsonLoadConfig(utils.ZEBRA_JSON_FILE, &jsonRoutes)
	Expect(err).To(BeNil(), "load route config error: %+v", err)
	if len(routes) != 0 {
		for _, r := range routes {
			rtEntry := &utils.ZebraRoute{}
			if r.Target == "" {
				rtEntry = utils.NewZebraRoute().SetDst(r.Destination).SetDistance(r.Distance).SetNextHop(utils.BLACKHOLE_ROUTE)
			} else {
				rtEntry = utils.NewZebraRoute().SetDst(r.Destination).SetNextHop(r.Target).SetDistance(r.Distance)
			}
			flag := false
			for _, j := range jsonRoutes {
				if *j == *rtEntry {
					flag = true
				}
			}
			Expect(flag).To(BeTrue(), "route entry[%+v] should exist", rtEntry)
		}
	}

	if len(routesDeleted) != 0 {
		for _, r := range routesDeleted {
			rtEntry := &utils.ZebraRoute{}
			if r.Target == "" {
				rtEntry = utils.NewZebraRoute().SetDst(r.Destination).SetDistance(r.Distance).SetNextHop(utils.BLACKHOLE_ROUTE)
			} else {
				rtEntry = utils.NewZebraRoute().SetDst(r.Destination).SetNextHop(r.Target).SetDistance(r.Distance)
			}
			flag := false
			for _, j := range jsonRoutes {
				if *j == *rtEntry {
					flag = true
				}
			}
			Expect(flag).To(BeFalse(), "route entry[%+v] should be delete", rtEntry)
		}
	}
}
