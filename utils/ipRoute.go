package utils

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"strconv"
	"strings"
)

const (
	POLICY_ROUTE_TABLE_FILE      = "/etc/iproute2/rt_tables"
	POLICY_ROUTE_TABLE_FILE_TEMP = "/home/vyos/zvr/.zs_rt_tables"
	VYOSHA_POLICY_ROUTE_SCRIPT   = "/home/vyos/zvr/keepalived/script/policyRoutes.sh"
)

type ZStackRouteTable struct {
	TableId int
	Alias   string
}

func (t ZStackRouteTable) toString() string {
	return fmt.Sprintf("%d %s", t.TableId, t.Alias)
}

func (t ZStackRouteTable) flushCommand() string {
	return fmt.Sprintf("sudo ip route flush table %d", t.TableId)
}

func GetZStackRouteTables() []ZStackRouteTable {
	var tables []ZStackRouteTable
	content, err := ioutil.ReadFile(POLICY_ROUTE_TABLE_FILE)
	if err != nil {
		log.Debugf("read file: %s, failed: %s", POLICY_ROUTE_TABLE_FILE, err)
		return tables
	}

	log.Debugf("%s contents: %s", POLICY_ROUTE_TABLE_FILE, content)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		if line[0] == '#' {
			continue
		}

		items := strings.Fields(line)
		if strings.Contains(items[1], PolicyRouteChainPrefix) {
			tableId, _ := strconv.Atoi(items[0])
			t := ZStackRouteTable{TableId: tableId, Alias: items[1]}
			tables = append(tables, t)
		}
	}

	return tables
}

func SyncZStackRouteTables(tables []ZStackRouteTable) error {
	bash := Bash{
		Command: fmt.Sprintf("cp %s %s; sed -i '/zs-rt-/d' %s", POLICY_ROUTE_TABLE_FILE, POLICY_ROUTE_TABLE_FILE_TEMP, POLICY_ROUTE_TABLE_FILE_TEMP),
	}
	ret, _, e, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return fmt.Errorf("create temp route table file failed: %s", e)
	}

	var cmds []string
	for _, t := range tables {
		cmds = append(cmds, t.toString())
	}
	if len(cmds) > 0 {
		bash = Bash{
			Command: fmt.Sprintf("cat <<EOF >> %s \n%s \nEOF\n sudo mv %s %s", POLICY_ROUTE_TABLE_FILE_TEMP, strings.Join(cmds, "\n"),
				POLICY_ROUTE_TABLE_FILE_TEMP, POLICY_ROUTE_TABLE_FILE),
		}
	} else {
		bash = Bash{
			Command: fmt.Sprintf("sudo mv %s %s", POLICY_ROUTE_TABLE_FILE_TEMP, POLICY_ROUTE_TABLE_FILE),
		}
	}
	ret, _, e, err = bash.RunWithReturn()
	if err != nil || ret != 0 {
		return fmt.Errorf("copy temp route table file failed: %s", e)
	}

	return nil
}

type ZStackRouteEntry struct {
	TableId         int
	DestinationCidr string
	NextHopIp       string
	NicName         string
	Distance        int
}

func (e ZStackRouteEntry) Equal(b ZStackRouteEntry) error {
	if e.TableId != b.TableId {
		return fmt.Errorf("tableId is different, %d:%d", e.TableId, b.TableId)
	}
	
	if e.DestinationCidr != b.DestinationCidr {
		return fmt.Errorf("destinationCidr is different, %s:%s", e.DestinationCidr, b.DestinationCidr)
	}
	
	if e.Distance != b.Distance {
		return fmt.Errorf("distance is different, %d:%d", e.Distance, b.Distance)
	}
	
	if e.NicName != "" {
		if e.NicName != b.NicName {
			return fmt.Errorf("nicName is different, %s:%s", e.NicName, b.NicName)
		}
	} else {
		if e.NextHopIp != b.NextHopIp {
			return fmt.Errorf("nextHopIp is different, %s:%s", e.NextHopIp, b.NextHopIp)
		}
	}
	
	return nil
}

func (e ZStackRouteEntry) addCommand() string {
	if e.NextHopIp != "" {
		if e.Distance != 0 {
			return fmt.Sprintf("sudo ip route add %s metric %d via %s table %d",
				e.DestinationCidr, e.Distance, e.NextHopIp, e.TableId)
		} else {
			return fmt.Sprintf("sudo ip route add %s via %s table %d",
				e.DestinationCidr, e.NextHopIp, e.TableId)
		}
	} else if e.NicName != "" {
		return fmt.Sprintf("sudo ip route add %s dev %s table %d",
			e.DestinationCidr, e.NicName, e.TableId)
	} else {
		log.Debugf("can not add route entry,because nexthopIp or nicName is null")
		return ""
	}
}

func (e ZStackRouteEntry) deleteCommand() string {
	if e.NextHopIp != "" {
		if e.Distance != 0 {
			return fmt.Sprintf("sudo ip route del %s metric %d via %s table %d",
				e.DestinationCidr, e.Distance, e.NextHopIp, e.TableId)
		} else {
			return fmt.Sprintf("sudo ip route del %s via %s table %d",
				e.DestinationCidr, e.NextHopIp, e.TableId)
		}
	} else if e.NicName != "" {
		return fmt.Sprintf("sudo ip route del %s dev %s table %d",
			e.DestinationCidr, e.NicName, e.TableId)
	} else {
		log.Debugf("can not del route entry,because nexthopIp or nicName is null")
		return ""
	}

}

func GetCurrentRouteEntries(tableId int) []ZStackRouteEntry {
	var entries []ZStackRouteEntry
	bash := Bash{
		Command: fmt.Sprintf("ip route show table %d", tableId),
	}
	ret, result, _, err := bash.RunWithReturn()
	if err == nil && ret == 0 {
		result = strings.TrimSpace(result)
		lines := strings.Split(result, "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}

			items := strings.Fields(line)
			distance := 0
			nicName := ""
			for i, item := range items {
				if item == "metric" {
					distance, _ = strconv.Atoi(items[i+1])
				}
			}

			if items[0] == "default" {
				e := ZStackRouteEntry{
					TableId:         tableId,
					DestinationCidr: "0.0.0.0/0",
					NextHopIp:       items[2],
					Distance:        distance,
				}
				entries = append(entries, e)
			} else if items[1] == "via" {
				if items[3] == "dev" {
					nicName = items[4]
				}
				e := ZStackRouteEntry{
					TableId:         tableId,
					DestinationCidr: items[0],
					NextHopIp:       items[2],
					NicName:         nicName,
					Distance:        distance,
				}
				entries = append(entries, e)
			} else if items[1] == "dev" {
				e := ZStackRouteEntry{
					TableId:         tableId,
					DestinationCidr: items[0],
					NicName:         items[2],
					Distance:        distance,
				}
				entries = append(entries, e)
			}
		}
	}

	return entries
}

func SyncRouteEntries(currTables []ZStackRouteTable, entryMap map[int][]ZStackRouteEntry) error {
	var newCmds []string
	/* delete route tables */
	for _, table := range currTables {
		if _, ok := entryMap[table.TableId]; !ok {
			newCmds = append(newCmds, table.flushCommand())
		}
	}

	for tableId, entries := range entryMap {
		currEntries := GetCurrentRouteEntries(tableId)
		/* delete old entries that is not needed */
		for _, oe := range currEntries {
			exist := false
			for _, ne := range entries {
				if oe.Equal(ne) == nil {
					exist = true
					break
				}
			}

			if !exist {
				newCmds = append(newCmds, oe.deleteCommand())
			}
		}

		/* add new entries that is added */
		for _, ne := range entries {
			exist := false
			for _, oe := range currEntries {
				if oe.Equal(ne) == nil {
					exist = true
					break
				}
			}

			if !exist {
				newCmds = append(newCmds, ne.addCommand())
			}
		}
	}

	if len(newCmds) == 0 {
		return nil
	}

	writePolicyRouteHaScript(entryMap)

	bash := Bash{
		Command: strings.Join(newCmds, ";"),
	}
	ret, _, e, err := bash.RunWithReturn()
	if err != nil || e != "" || ret != 0 {
		return fmt.Errorf("sync ip route: %s, error: %s, ret: %d", strings.Join(newCmds, ";"), e, ret)
	}

	return nil
}

func writePolicyRouteHaScript(entryMap map[int][]ZStackRouteEntry) error {
	if !IsHaEnabled() {
		return nil
	}

	var routes []string
	for _, entries := range entryMap {
		for _, ne := range entries {
			routes = append(routes, ne.addCommand())
		}
	}

	return ioutil.WriteFile(VYOSHA_POLICY_ROUTE_SCRIPT, []byte(strings.Join(routes, "\n")), 0755)
}
