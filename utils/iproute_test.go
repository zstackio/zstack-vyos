package utils

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"sort"
)

var _ = Describe("linux ip route table test", func() {
	BeforeEach(func() {
		InitLog(VYOS_UT_LOG_FOLDER+"iproute_test.log", false)
	})

	It("test ip route table", func() {
		tables := GetZStackRouteTables()
		Expect(tables).NotTo(BeNil(), fmt.Sprintf("there are existed route tables: %+v", tables))

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

var _ = Describe("linux ip route entry test", func() {
	BeforeEach(func() {
		InitLog(VYOS_UT_LOG_FOLDER+"iproute_test.log", false)
	})

	It("test ip route entry", func() {

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
