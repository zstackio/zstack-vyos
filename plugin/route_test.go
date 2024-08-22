package plugin

import (
	"fmt"
	"strings"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = XDescribe("route_test", func() {
	var (
		nextHopInPubL3                     string
		nextHopInPubL32                    string
		nextHopInmgt                       string
		r0, r1, r2, r3, r4, r5, r6, r7, r8 routeInfo
		nicCmd                             *configureNicCmd
	)

	It("prepare for route set", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"route_test.log", false)
		utils.CleanTestEnvForUT()
		utils.InitVyosVersion()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)

		nextHopInPubL3, _ = utils.GetFreePubL3Ip()
		nextHopInPubL32, _ = utils.GetFreePubL3Ip()
		nextHopInmgt, _ = utils.GetFreeMgtIp()

		r0 = routeInfo{Destination: "172.16.0.0/12", Target: utils.GetMgtGateway(), Distance: 1}
		r1 = routeInfo{Destination: "1.1.1.0/24", Target: nextHopInPubL3, Distance: 100}
		r2 = routeInfo{Destination: "1.1.2.0/24", Target: nextHopInPubL3, Distance: 110}
		r3 = routeInfo{Destination: "1.1.3.0/24", Target: nextHopInmgt, Distance: 120}
		r4 = routeInfo{Destination: "1.1.4.0/24", Target: nextHopInmgt, Distance: 130}
		r5 = routeInfo{Destination: "1.1.5.0/24", Target: "", Distance: 80}
		r6 = routeInfo{Destination: "1.1.6.0/24", Target: "", Distance: 90}
		r7 = routeInfo{Destination: "1.1.1.0/24", Target: nextHopInPubL32, Distance: 100}
		r8 = routeInfo{Destination: "1.1.3.0/24", Target: nextHopInmgt, Distance: 130}

		nicCmd = &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)

		bash := utils.Bash{
			Command: fmt.Sprintf("ip link set up dev %s", utils.PubNicForUT.Name),
			Sudo:    true,
		}
		bash.Run()
	})

	It("route set", func() {
		routes := []routeInfo{r0, r1, r2, r3, r4, r5, r6}
		setRoutes(routes)
		checkRoutes(routes, []routeInfo{})
	})

	It("route set again", func() {
		routes := []routeInfo{r0, r1, r2, r3, r4, r5, r6}
		setRoutes(routes)
		checkRoutes(routes, []routeInfo{})
	})

	It("route change", func() {
		routes := []routeInfo{r0, r2, r4, r5, r6, r7, r8}
		routesDelete := []routeInfo{r1, r3}
		setRoutes(routes)
		checkRoutes(routes, routesDelete)
	})

	It("route add", func() {
		routes := []routeInfo{r0, r1, r2, r3, r4, r5, r6}
		setRoutes(routes)
		checkRoutes(routes, []routeInfo{})
	})

	It("route delte", func() {
		routes1 := []routeInfo{r0}
		setRoutes(routes1)
		checkRoutes(routes1, []routeInfo{r1, r2, r3, r4, r5, r6})
	})

	It("release after route delte", func() {
		utils.CleanTestEnvForUT()
	})

})

func checkRoutes(routes []routeInfo, routesDeleted []routeInfo) {
	tree := server.NewParserFromShowConfiguration().Tree
	currentRoutes := getCurrentStaticRoutes(tree)

	for _, r1 := range routes {
		found := false
		for _, r2 := range currentRoutes {
			if r2 == r1 {
				found = true
				break
			}
		}

		Expect(found).To(BeTrue(), "route [%+v] check add failed", r1)
	}

	for _, r1 := range routesDeleted {
		found := false
		for _, r2 := range currentRoutes {
			if r2 == r1 {
				found = true
				break
			}
		}

		Expect(found).To(BeFalse(), "route [%+v] check add failed", r1)
	}

	/* check linux ip route */
	ret, o, _, err := getLinuxRoutes()
	Expect(ret != 0 || err != nil).To(BeFalse(), "get linux router failed", err)

	for _, r1 := range routes {
		if r1.Target != "" {
			r := fmt.Sprintf("%s [%d/0] via %s", r1.Destination, r1.Distance, r1.Target)
			Expect(strings.Contains(o, r)).To(BeTrue(), "get linux route [%s] failed", r)
		} else {
			var r string
			if utils.Vyos_version == utils.VYOS_1_1_7 {
				r = fmt.Sprintf("%s [%d/0] is directly connected, Null0, bh", r1.Destination, r1.Distance)
			} else {
				r = fmt.Sprintf("%s [%d/0] unreachable (blackhole)", r1.Destination, r1.Distance)
			}
			Expect(strings.Contains(o, r)).To(BeTrue(), "get linux route [%s] failed", r)
		}
	}

	for _, r1 := range routesDeleted {
		if r1.Target != "" {
			r := fmt.Sprintf("S>* %s [%d/0] via %s", r1.Destination, r1.Distance, r1.Target)
			Expect(strings.Contains(o, r)).To(BeFalse(), "delete linux route [%s] failed", r)
		} else {
			var r string
			if utils.Vyos_version == utils.VYOS_1_2 {
				r = fmt.Sprintf("%s [%d/0] is directly connected, Null0, bh", r1.Destination, r1.Distance)
			} else {
				r = fmt.Sprintf("%s [%d/0] unreachable (blackhole)", r1.Destination, r1.Distance)
			}
			Expect(strings.Contains(o, r)).To(BeFalse(), "delete linux route [%s] failed", r)
		}
	}
}
