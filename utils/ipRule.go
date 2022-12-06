package utils

import (
	"fmt"
	"strconv"
	"strings"
)

type ZStackIpRule struct {
	Fwmark  uint64
	From    string
	TableId uint64
}

func getIpRouteTableAlias(tableId uint64) string {
	return fmt.Sprintf("%s%d", PolicyRouteChainPrefix, tableId)
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

	return true
}

func (a ZStackIpRule) addBashCommand() string {
	if a.Fwmark == 0 {
		return fmt.Sprintf("sudo ip rule add from %s table %s", a.From, getIpRouteTableAlias(a.TableId))
	} else {
		return fmt.Sprintf("sudo ip rule add fwmark %d table %s", a.Fwmark, getIpRouteTableAlias(a.TableId))
	}
}

func (a ZStackIpRule) delBashCommand() string {
	if a.Fwmark == 0 {
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

	for _, line := range lines {
		items := strings.Fields(line)

		if items[3] == "fwmark" {
			mark, _ := strconv.ParseUint(strings.Replace(strings.TrimSpace(items[4]), "0x", "", 1), 16, 64)
			tableId, _ := strconv.Atoi(strings.Replace(strings.TrimSpace(items[6]), PolicyRouteChainPrefix, "", 1))
			rule := ZStackIpRule{Fwmark: mark, From: "", TableId: uint64(tableId)}
			rules = append(rules, rule)
		} else {
			tableId, _ := strconv.Atoi(strings.Replace(strings.TrimSpace(items[4]), PolicyRouteChainPrefix, "", 1))
			rule := ZStackIpRule{Fwmark: 0, From: items[2], TableId: uint64(tableId)}
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
			newCmds = append(newCmds, crule.delBashCommand())
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
			newCmds = append(newCmds, nrule.addBashCommand())
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
