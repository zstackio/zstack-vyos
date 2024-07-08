package utils

import (
	"fmt"
	"strconv"
	"strings"
)

type ZStackIpRule struct {
	Fwmark  uint64
	From    string
	To		  string
	TableId int
}

func getIpRouteTableAlias(tableId int) string {
	if tableId == RT_TABLES_MGMT {
		return "mgmt"
	} else {
		return fmt.Sprintf("%s%d", PolicyRouteChainPrefix, tableId)
	}
}

func (a ZStackIpRule) Equal(b ZStackIpRule) bool {
	if a.TableId != b.TableId {
		return false
	}

	if a.Fwmark != b.Fwmark {
		return false
	}

	if a.From != b.From {
		return false
	}

	if a.To != b.To {
		return false
	}

	return true
}

func (a ZStackIpRule) AddBashCommand() string {
	if a.To != "" {
		return fmt.Sprintf("sudo ip rule add to %s table %s", a.To, getIpRouteTableAlias(a.TableId))
	} else if a.Fwmark == 0 {
		return fmt.Sprintf("sudo ip rule add from %s table %s", a.From, getIpRouteTableAlias(a.TableId))
	} else {
		return fmt.Sprintf("sudo ip rule add fwmark %d table %s", a.Fwmark, getIpRouteTableAlias(a.TableId))
	}
}

func (a ZStackIpRule) DelBashCommand() string {
	if a.To != "" {
		return fmt.Sprintf("sudo ip rule del to %s table %s", a.To, getIpRouteTableAlias(a.TableId))
	} else if a.Fwmark == 0 {
		return fmt.Sprintf("sudo ip rule del from %s table %d", a.From, a.TableId)
	} else {
		return fmt.Sprintf("sudo ip rule del fwmark %d table %d", a.Fwmark, a.TableId)
	}
}

func GetZStackIpRules() []ZStackIpRule {
	var rules []ZStackIpRule
	bash := Bash{
		Command: fmt.Sprintf("ip rule | grep %s", PolicyRouteChainPrefix),
	}
	ret, o, _, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return rules
	}

	o = strings.TrimSpace(o)
	lines := strings.Split(o, "\n")

	rt_tables := GetZStackRouteTables()
	rt_tables_map := map[string]int{}
	for _, table := range rt_tables {
		rt_tables_map[table.Alias] = table.TableId
	}

	for _, line := range lines {
		items := strings.Fields(line)

		if items[3] == "fwmark" {
			mark, _ := strconv.ParseUint(strings.Replace(strings.TrimSpace(items[4]), "0x", "", 1), 16, 64)
			tableId, _ := rt_tables_map[items[6]]
			rule := ZStackIpRule{Fwmark: mark, From: "", TableId: tableId}
			rules = append(rules, rule)
		} else if items[3] == "to" {
			tableId, _ := rt_tables_map[items[6]]
			rule := ZStackIpRule{Fwmark: 0, To: items[4], TableId: tableId}
			rules = append(rules, rule)
		} else {
			tableId, _ := rt_tables_map[items[4]]
			rule := ZStackIpRule{Fwmark: 0, From: items[2], TableId: tableId}
			rules = append(rules, rule)
		}
	}

	return rules
}

func SyncZStackIpRules(currRules, rules []ZStackIpRule) error {
	var newCmds []string

	/* delete ip rules that is not in new rules */
	for _, crule := range currRules {
		exist := false
		for _, nrule := range rules {
			if crule.Equal(nrule) {
				exist = true
				break
			}
		}

		if !exist {
			newCmds = append(newCmds, crule.DelBashCommand())
		}
	}

	/* add new ip rules that is not in current rules */
	for _, nrule := range rules {
		exist := false
		for _, crule := range currRules {
			if crule.Equal(nrule) {
				exist = true
				break
			}
		}

		if !exist {
			newCmds = append(newCmds, nrule.AddBashCommand())
		}
	}

	if len(newCmds) == 0 {
		return nil
	}

	bash := Bash{
		Command: strings.Join(newCmds, ";"),
	}
	ret, _, e, err := bash.RunWithReturn()

	if err != nil || e != "" || ret != 0 {
		return fmt.Errorf("sync ip rules: %s, error: %s, ret: %d", strings.Join(newCmds, ";"), e, ret)
	}

	return nil
}
