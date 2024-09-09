package utils

import (
	"fmt"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = XDescribe("iproute_test SetZStackRoute", func() {
	BeforeEach(func() {
		InitLog(GetVyosUtLogDir()+"iproute_test.log", IsRuingUT())
	})

	It("test set&remove zstack route", func() {
		ip := "88.1.1.1"
		intfip := "10.1.1.2/24"
		gw := "10.1.1.1"
		bash := Bash{
			Command: fmt.Sprintf("sudo ip addr add %s dev eth0", intfip),
		}
		ret, _, _, _ := bash.RunWithReturn()
		Expect(ret).To(Equal(0), "set test env failed.")
		if ret == 0 {
			err := SetZStackRoute(ip, "eth0", gw)
			Expect(err).To(BeNil(), "set zstack route failed.")

			err = RemoveZStackRoute(ip)
			Expect(err).To(BeNil(), "remove existed route failed.")

			err = RemoveZStackRoute("99.1.1.1")
			Expect(err).To(BeNil(), "remove non-existent route failed.")

			bash = Bash{
				Command: fmt.Sprintf("sudo ip addr del %s dev eth0", intfip),
			}
			bash.RunWithReturn()
		}

	})
})

var _ = XDescribe("iproute_test SyncZStackRouteTables", func() {
	BeforeEach(func() {
		InitLog(GetVyosUtLogDir()+"iproute_test.log", IsRuingUT())
	})

	It("test ip route table", func() {
		tables := GetZStackRouteTables()
		Expect(len(tables)).To(BeZero(), fmt.Sprintf("there are existed route tables: %+v", tables))

		t1 := ZStackRouteTable{TableId: 181, Alias: "zs-rt-181"}
		t2 := ZStackRouteTable{TableId: 182, Alias: "zs-rt-182"}
		t3 := ZStackRouteTable{TableId: 183, Alias: "zs-rt-183"}
		setTables := []ZStackRouteTable{t1}
		SyncZStackRouteTables([]ZStackRouteTable{t1})
		tables = GetZStackRouteTables()
		checkRouteTables(setTables, tables)

		setTables = []ZStackRouteTable{t1, t2, t3}
		SyncZStackRouteTables(setTables)
		tables = GetZStackRouteTables()
		checkRouteTables(setTables, tables)

		setTables = []ZStackRouteTable{t1, t3}
		SyncZStackRouteTables(setTables)
		tables = GetZStackRouteTables()
		checkRouteTables(setTables, tables)

		setTables = []ZStackRouteTable{}
		SyncZStackRouteTables(setTables)
		tables = GetZStackRouteTables()
		checkRouteTables(setTables, tables)
	})
})

var _ = XDescribe("iproute_test SyncRouteEntries", func() {
	BeforeEach(func() {
		InitLog(GetVyosUtLogDir()+"iproute_test.log", IsRuingUT())
	})

	It("test default ip route", func() {
		t1 := ZStackRouteTable{TableId: 254, Alias: "main"}
		setTables := []ZStackRouteTable{t1}
		routeTableMain := GetCurrentRouteEntries(254)

		/* nexthop is in direct network */
		entry1 := ZStackRouteEntry{
			TableId:         254,
			DestinationCidr: "2.2.2.0/24",
			NextHopIp:       MgtNicForUT.Gateway,
			Distance:        128,
		}

		entry2 := ZStackRouteEntry{
			TableId:         254,
			DestinationCidr: "2.2.3.0/24",
			NextHopIp:       PubNicForUT.Gateway,
			Distance:        128,
		}

		/* nexthop is not in direct network */
		entry3 := ZStackRouteEntry{
			TableId:         254,
			DestinationCidr: "3.2.2.0/24",
			NextHopIp:       "2.2.2.1",
			Distance:        128,
		}

		/* blackhole is not in direct network */
		entry4 := ZStackRouteEntry{
			TableId:         254,
			DestinationCidr: "3.2.2.0/24",
			NicName:         "null0",
			Distance:        128,
		}

		routeTableMain1 := append(routeTableMain, []ZStackRouteEntry{entry1, entry2, entry3, entry4}...)
		SyncRouteEntries(setTables, map[int][]ZStackRouteEntry{254: routeTableMain1})

		routeTableMain2 := GetCurrentRouteEntries(254)
		checkRouteEntry(routeTableMain2, routeTableMain1)

		SyncRouteEntries(setTables, map[int][]ZStackRouteEntry{254: routeTableMain})
		routeTableMain3 := GetCurrentRouteEntries(254)
		checkRouteEntry(routeTableMain3, routeTableMain)
	})
})

func checkRouteTables(setTables, getTables []ZStackRouteTable) {
	Expect(len(setTables) != len(getTables)).NotTo(BeTrue(),
		fmt.Sprintf("set tables [%+v] are different from get tables [%+v]", setTables, getTables))

	sort.Slice(setTables, func(i, j int) bool {
		return setTables[i].TableId < setTables[j].TableId
	})

	sort.Slice(getTables, func(i, j int) bool {
		return setTables[i].TableId < setTables[j].TableId
	})

	for i := 0; i < len(setTables); i++ {
		Expect(setTables[i] != getTables[i]).NotTo(BeTrue(),
			fmt.Sprintf("table in set [%+v] are different from get [%+v]", setTables[i], getTables[i]))
	}
}

func checkRouteEntry(newEntries, oldEntries []ZStackRouteEntry) {
	for _, ne := range newEntries {
		found := false
		for _, oe := range oldEntries {
			if ne.Equal(oe) != nil {
				found = true
			}
		}

		Expect(found).To(BeTrue(),
			fmt.Sprintf("new entry: %+v should not be added", ne))
	}

	log.Debugf("new entries: %+v", newEntries)
	for _, ne := range oldEntries {
		found := false
		for _, oe := range newEntries {
			if ne.Equal(oe) != nil {
				found = true
			}
		}

		Expect(found).To(BeTrue(),
			fmt.Sprintf("old entry: %+v should be added", ne))
	}
}
