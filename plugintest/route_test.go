package plugintest

import (
	"zstack-vyos/plugin"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func IsRouteExisted(rts []utils.ZStackRouteEntry, rinfo plugin.RouteInfo) bool {
	for _, rt := range rts {
		if rt.DestinationCidr == rinfo.Destination &&
			rt.NextHopIp == rinfo.Target &&
			rt.Distance == rinfo.Distance {
			return true
		}
	}

	return false
}

var _ = Describe("routingTable test", func() {

	Context("vpc linux routingTable test", func() {
		env := NewVpcIpv4Env()
		var r1, r2, r3, r4, r5, r6, r7, r8 plugin.RouteInfo
		It("routingTable test: prepare env", func() {
			env.SetupBootStrap()
			r1 = plugin.RouteInfo{Destination: "1.1.1.0/24", Target: "10.1.1.101", Distance: 100}
			r2 = plugin.RouteInfo{Destination: "1.1.2.0/24", Target: "10.1.1.101", Distance: 110}
			r3 = plugin.RouteInfo{Destination: "1.1.3.0/24", Target: "10.1.2.101", Distance: 120}
			r4 = plugin.RouteInfo{Destination: "1.1.4.0/24", Target: "10.1.2.101", Distance: 130}
			r5 = plugin.RouteInfo{Destination: "1.1.5.0/24", Target: "10.1.1.101", Distance: 80}
			r6 = plugin.RouteInfo{Destination: "1.1.6.0/24", Target: "10.1.1.101", Distance: 90}
			r7 = plugin.RouteInfo{Destination: "1.1.6.0/24"}
			r8 = plugin.RouteInfo{Destination: "1.1.5.0/24"}
		})

		It("linux routingTable test:", func() {
			routes := []plugin.RouteInfo{r1, r2, r3, r4, r5, r6, r7, r8}
			plugin.SetZebraRoutes(routes)

			rts := utils.GetCurrentRouteEntries(utils.ROUTETABLE_ID_MAIN)
			r1exised := IsRouteExisted(rts, r1)
			Expect(r1exised).To(BeTrue(), "r1 added")
			r2exised := IsRouteExisted(rts, r2)
			Expect(r2exised).To(BeTrue(), "r2 added")
			r3exised := IsRouteExisted(rts, r3)
			Expect(r3exised).To(BeTrue(), "r3 added")
			r4exised := IsRouteExisted(rts, r4)
			Expect(r4exised).To(BeTrue(), "r4 added")
			r5exised := IsRouteExisted(rts, r5)
			Expect(r5exised).To(BeTrue(), "r5 added")
			r6exised := IsRouteExisted(rts, r6)
			Expect(r6exised).To(BeTrue(), "r6 added")
			r7exised := IsRouteExisted(rts, r7)
			Expect(r7exised).To(BeFalse(), "r7 added")
			r8exised := IsRouteExisted(rts, r8)
			Expect(r8exised).To(BeFalse(), "r8 added")

			plugin.GetLinuxRoutes()

			routes = []plugin.RouteInfo{r1, r2}
			plugin.SetZebraRoutes(routes)

			rts = utils.GetCurrentRouteEntries(utils.ROUTETABLE_ID_MAIN)
			r1exised = IsRouteExisted(rts, r1)
			Expect(r1exised).To(BeTrue(), "r1 added")
			r2exised = IsRouteExisted(rts, r2)
			Expect(r2exised).To(BeTrue(), "r2 added")
			r3exised = IsRouteExisted(rts, r3)
			Expect(r3exised).To(BeFalse(), "r3 deleted")
			r4exised = IsRouteExisted(rts, r4)
			Expect(r4exised).To(BeFalse(), "r4 deleted")
			r5exised = IsRouteExisted(rts, r5)
			Expect(r5exised).To(BeFalse(), "r5 deleted")
			r6exised = IsRouteExisted(rts, r6)
			Expect(r6exised).To(BeFalse(), "r6 deleted")
			r7exised = IsRouteExisted(rts, r7)
			Expect(r7exised).To(BeFalse(), "r7 deleted")
			r8exised = IsRouteExisted(rts, r8)
			Expect(r8exised).To(BeFalse(), "r8 deleted")

			routes = []plugin.RouteInfo{r1, r2, r7, r8}
			plugin.SetZebraRoutes(routes)

			rts = utils.GetCurrentRouteEntries(utils.ROUTETABLE_ID_MAIN)
			r1exised = IsRouteExisted(rts, r1)
			Expect(r1exised).To(BeTrue(), "r1 added")
			r2exised = IsRouteExisted(rts, r2)
			r7exised = IsRouteExisted(rts, r7)
			Expect(r7exised).To(BeTrue(), "r7 deleted")
			r8exised = IsRouteExisted(rts, r8)
			Expect(r8exised).To(BeTrue(), "r8 deleted")

			routes = []plugin.RouteInfo{}
			plugin.SetZebraRoutes(routes)

			rts = utils.GetCurrentRouteEntries(utils.ROUTETABLE_ID_MAIN)
			r1exised = IsRouteExisted(rts, r1)
			Expect(r1exised).To(BeFalse(), "r1 deleted")
			r2exised = IsRouteExisted(rts, r2)
			Expect(r2exised).To(BeFalse(), "r1 deleted")
			r7exised = IsRouteExisted(rts, r7)
			Expect(r1exised).To(BeFalse(), "r1 deleted")
			r7exised = IsRouteExisted(rts, r8)
			Expect(r2exised).To(BeFalse(), "r1 deleted")
		})

		It("routingTable test: destroy env", func() {
			env.DestroyBootStrap()
		})
	})
})
