package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	POLICY_ROUTE_TABLE_FILE = "/etc/iproute2/rt_tables"

	ROUTETABLE_ID_MIN  = 1
	ROUTETABLE_ID_MAX  = 250
	ROUTETABLE_ID_MAIN = 254
)

func getPolicyRouterTableFileTemp() string {
	return filepath.Join(GetZvrRootPath(), ".zs_rt_tables")
}

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
	content, err := os.ReadFile(POLICY_ROUTE_TABLE_FILE)
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
		Command: fmt.Sprintf("cp %s %s; sed -i '/zs-rt-/d' %s", POLICY_ROUTE_TABLE_FILE, getPolicyRouterTableFileTemp(), getPolicyRouterTableFileTemp()),
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
			Command: fmt.Sprintf("cat <<EOF >> %s \n%s \nEOF\n sudo mv %s %s", getPolicyRouterTableFileTemp(), strings.Join(cmds, "\n"),
				getPolicyRouterTableFileTemp(), POLICY_ROUTE_TABLE_FILE),
		}
	} else {
		bash = Bash{
			Command: fmt.Sprintf("sudo mv %s %s", getPolicyRouterTableFileTemp(), POLICY_ROUTE_TABLE_FILE),
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

	if e.Distance != 0 && e.Distance != b.Distance {
		return fmt.Errorf("distance is different, %d:%d", e.Distance, b.Distance)
	}

	if e.NextHopIp != "" && e.NextHopIp != b.NextHopIp {
		return fmt.Errorf("nextHopIp is different, %s:%s", e.NextHopIp, b.NextHopIp)
	}

	if e.NicName != "" && e.NicName != b.NicName {
		return fmt.Errorf("nicName is different, %s:%s", e.NicName, b.NicName)
	}

	return nil
}

func (e ZStackRouteEntry) addCommand() string {
	if e.TableId == ROUTETABLE_ID_MAIN {
		if e.NextHopIp != "" {
			if e.Distance != 0 {
				return fmt.Sprintf("ip route %s %s %d", e.DestinationCidr, e.NextHopIp, e.Distance)
			} else {
				return fmt.Sprintf("ip route %s %s", e.DestinationCidr, e.NextHopIp)
			}
		} else if e.NicName != "" {
			if e.Distance != 0 {
				return fmt.Sprintf("ip route %s %s %d",
					e.DestinationCidr, e.NicName, e.Distance)
			} else {
				return fmt.Sprintf("ip route %s %s",
					e.DestinationCidr, e.NicName)
			}
		} else {
			log.Debugf("can not add route entry,because nexthopIp and nicName is null")
			return ""
		}
	}

	if e.NextHopIp != "" {
		if e.Distance != 0 {
			return fmt.Sprintf("ip route %s %s table %d %d", e.DestinationCidr, e.NextHopIp, e.TableId, e.Distance)
		} else {
			return fmt.Sprintf("ip route %s %s table %d", e.DestinationCidr, e.NextHopIp, e.TableId)
		}
	} else if e.NicName != "" {
		if e.Distance != 0 {
			return fmt.Sprintf("ip route %s %s table %d %d",
				e.DestinationCidr, e.NicName, e.TableId, e.Distance)
		} else {
			return fmt.Sprintf("ip route %s %s table %d",
				e.DestinationCidr, e.NicName, e.TableId)
		}
	} else {
		log.Debugf("can not add route entry,because nexthopIp and nicName is null")
		return ""
	}
}

func (e ZStackRouteEntry) deleteCommand() string {
	if e.TableId == ROUTETABLE_ID_MAIN {
		if e.NextHopIp != "" {
			if e.Distance != 0 {
				return fmt.Sprintf("no ip route %s %s %d", e.DestinationCidr, e.NextHopIp, e.Distance)
			} else {
				return fmt.Sprintf("no ip route %s %s", e.DestinationCidr, e.NextHopIp)
			}
		} else if e.NicName != "" {
			if e.Distance != 0 {
				return fmt.Sprintf("no ip route %s %s %d",
					e.DestinationCidr, e.NicName, e.Distance)
			} else {
				return fmt.Sprintf("no ip route %s %s",
					e.DestinationCidr, e.NicName)
			}
		} else {
			log.Debugf("can not del route entry,because nexthopIp and nicName is null")
			return ""
		}
	}

	if e.NextHopIp != "" {
		if e.Distance != 0 {
			return fmt.Sprintf("no ip route %s %s table %d %d", e.DestinationCidr, e.NextHopIp, e.TableId, e.Distance)
		} else {
			return fmt.Sprintf("no ip route %s %s table %d", e.DestinationCidr, e.NextHopIp, e.TableId)
		}
	} else if e.NicName != "" {
		if e.Distance != 0 {
			return fmt.Sprintf("no ip route %s %s table %d %d",
				e.DestinationCidr, e.NicName, e.TableId, e.Distance)
		} else {
			return fmt.Sprintf("no ip route %s %s table %d",
				e.DestinationCidr, e.NicName, e.TableId)
		}
	} else {
		log.Debugf("can not del route entry,because nexthopIp and nicName is null")
		return ""
	}
}

func GetCurrentRouteEntries(tableId int) []ZStackRouteEntry {
	/* some table can not be operate
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 0'
	% Unknown command.
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 1'
	table 1:

	Codes: K - kernel route, C - connected, S - static, R - RIP, O - OSPF,
	       I - ISIS, B - BGP, > - selected route, * - FIB route

	S>* 1.1.1.0/24 [1/0] via 172.16.1.1 (recursive via 172.25.0.1)
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 250'
	table 250:

	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 251'
	% Unknown command.
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 252'
	% Unknown command.
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 253'
	% Unknown command.
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 254'
	% Unknown command.
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 255'
	% Unknown command.
	**/

	if (tableId > ROUTETABLE_ID_MAX || tableId < ROUTETABLE_ID_MIN) && tableId != ROUTETABLE_ID_MAIN {
		panic("valid route table id range [1, 250]")
	}

	var entries []ZStackRouteEntry
	cmd := fmt.Sprintf("vtysh -c 'show ip route table %d' | grep ^S", tableId)
	if tableId == ROUTETABLE_ID_MAIN {
		cmd = fmt.Sprintf("vtysh -c 'show ip route' | grep ^S")
	}

	bash := Bash{
		Command: cmd,
	}
	/*
	  output format:
	  $ vtysh -c "show ip route table 2"  | grep "^S"
	  S>* 3.2.4.0/24 [100/0] is directly connected, eth1
	  S>* 3.2.5.0/24 [1/0] is directly connected, eth1
	  S>* 3.3.3.0/24 [200/0] via 1.1.1.2, eth2
	  $ vtysh -c "show ip route"  | grep "^S"
	   S>* 0.0.0.0/0 [1/0] via 172.25.0.1, eth1
	   S   2.2.2.0/24 [200/0] via 1.1.2.101
	   S>* 2.2.2.0/24 [128/0] via 1.1.2.100 (recursive via 172.25.0.1)
	   S>* 2.2.3.0/24 [128/0] is directly connected, Null0, bh
	   S>* 2.2.4.0/24 [120/0] via 1.1.2.104 (recursive via 172.25.0.1)
	   S>* 2.2.5.0/24 [120/0] via 1.1.2.104 (recursive via 172.25.0.1)
	   S>* 3.2.4.0/24 [2/0] via 1.1.1.104, eth2
	*/
	ret, result, _, err := bash.RunWithReturn()
	if err == nil && ret == 0 {
		result = strings.TrimSpace(result)
		lines := strings.Split(result, "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}

			items := strings.Fields(line)

			distances := strings.Split(items[2], "/")
			distance, _ := strconv.Atoi(distances[0][1:])

			if items[3] == "via" {
				nicName := ""
				if items[5] != "(recursive" {
					nicName = items[len(items)-1]
				}

				e := ZStackRouteEntry{
					TableId:         tableId,
					DestinationCidr: items[1],
					NextHopIp:       strings.TrimRight(items[4], ","), /* 1.1.1.2, */
					NicName:         nicName,
					Distance:        distance,
				}
				entries = append(entries, e)
			} else {
				nicName := items[len(items)-1] /* ethx or bh */
				if nicName == "bh" {
					nicName = "null0"
				}
				e := ZStackRouteEntry{
					TableId:         tableId,
					DestinationCidr: items[1],
					NicName:         nicName,
					Distance:        distance,
				}
				entries = append(entries, e)
			}
		}
	}

	return entries
}

func deleteRouteEntries(entries []ZStackRouteEntry) interface{} {
	cmds := []string{"vtysh -c 'configure terminal'"}
	for _, r := range entries {
		cmds = append(cmds, fmt.Sprintf("-c '%s'", r.deleteCommand()))
	}

	bash := Bash{
		Command: fmt.Sprintf("%s", strings.Join(cmds, " ")),
	}

	ret, _, e, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return fmt.Errorf("delete ip route: %s failed, because: %s", strings.Join(cmds, " "), e)
	}

	return nil
}

func addRouteEntries(entries []ZStackRouteEntry) interface{} {
	cmds := []string{"vtysh -c 'configure terminal'"}
	for _, r := range entries {
		cmds = append(cmds, fmt.Sprintf("-c '%s'", r.addCommand()))
	}

	bash := Bash{
		Command: fmt.Sprintf("%s", strings.Join(cmds, " ")),
	}

	ret, _, e, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return fmt.Errorf("add ip route: %s failed, because: %s", strings.Join(cmds, " "), e)
	}

	return nil
}

func SyncRouteEntries(currTables []ZStackRouteTable, entryMap map[int][]ZStackRouteEntry) error {
	var toDeleted []ZStackRouteEntry
	var toAdded []ZStackRouteEntry
	/* delete route tables */
	for _, table := range currTables {
		if _, ok := entryMap[table.TableId]; !ok {
			currEntries := GetCurrentRouteEntries(table.TableId)
			for _, r := range currEntries {
				toDeleted = append(toDeleted, r)
			}
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
				toDeleted = append(toDeleted, oe)
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
				toAdded = append(toAdded, ne)
			}
		}
	}

	if len(toDeleted) != 0 {
		deleteRouteEntries(toDeleted)
	}

	if len(toAdded) != 0 {
		addRouteEntries(toAdded)
	}

	return nil
}
