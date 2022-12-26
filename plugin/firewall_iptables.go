package plugin

import (
	"fmt"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/zstackio/zstack-vyos/utils"
)

func isFirewallChain(chainName string) bool {
	if strings.HasSuffix(chainName, ".in") {
		return true
	}

	if strings.HasSuffix(chainName, ".out") {
		return true
	}

	return false
}

func isNicFilterChain(chainName string) bool {
	if strings.HasSuffix(chainName, ".in") {
		return true
	}

	if strings.HasSuffix(chainName, ".out") {
		return true
	}

	if strings.HasSuffix(chainName, ".local") {
		return true
	}

	return false
}

func getRuleSetFromIpTable(table *utils.IpTables) map[string]*ruleSetInfo {
	/* rule set action like this:
	   	-A VYATTA_PRE_FW_FWD_HOOK -i eth1 -j eth1.in
	       -A VYATTA_PRE_FW_IN_HOOK -i eth1 -j eth1.local
	       -A VYATTA_FW_OUT_HOOK -o eth2 -j eth2.out
	       -A eth2.in -s 1.1.1.0/24 -d 2.2.2.0/24 -p udp -m comment --comment "eth2.in-1001" -m state --state INVALID,NEW,RELATED,ESTABLISHED -m multiport --dports 5000:6000 -m multiport --sports 8000:9000 -j RETURN
	   	-A eth2.in -m comment --comment "eth2.in-4000" -m state --state INVALID,NEW,RELATED,ESTABLISHED -j RETURN
	   	-A eth2.in -p icmp -m comment --comment "eth2.in-4001" -j RETURN
	   	-A eth2.in -m comment --comment "eth2.in-4002" -m state --state NEW,RELATED,ESTABLISHED -m set --match-set eip-group src -j RETURN
	   	-A eth2.in -m comment --comment "eth2.in-10000 default-action reject" -j REJECT --reject-with icmp-port-unreachable
	*/
	sets := make(map[string]*ruleSetInfo)

	for _, r := range table.Rules {
		if isNicFilterChain(r.GetAction()) {
			ruleSet := &ruleSetInfo{Name: r.GetAction(), Rules: []ruleInfo{}, ActionType: "accept"}
			sets[r.GetAction()] = ruleSet
		}

		if _, ok := sets[r.GetChainName()]; ok {
			if r.GetAction() == utils.IPTABLES_ACTION_LOG {
				sets[r.GetChainName()].EnableDefaultLog = true
			} else if utils.IsDefaultRule(r) {
				if r.GetAction() == utils.IPTABLES_ACTION_RETURN {
					r.SetAction(utils.IPTABLES_ACTION_ACCEPT)
				}
				sets[r.GetChainName()].ActionType = strings.ToLower(r.GetAction())
			} else {
				sets[r.GetChainName()].Rules = append(sets[r.GetChainName()].Rules, getRuleFromIpTableRule(r))
			}
		}
	}

	return sets
}

func getRuleFromIpTableRule(r *utils.IpTableRule) ruleInfo {
	var rule ruleInfo

	if r.GetAction() == utils.IPTABLES_ACTION_RETURN {
		r.SetAction(utils.IPTABLES_ACTION_ACCEPT)
	}
	rule.Action = strings.ToLower(r.GetAction())
	if r.GetDstIpset() != "" {
		rule.DestIp = r.GetDstIpset()
	} else if r.GetDstIp() != "" {
		rule.DestIp = getRuleIpInfoFromIpTableRule(r.GetDstIp())
	} else if r.GetDstIpRange() != "" {
		rule.DestIp = getRuleIpInfoFromIpTableRule(r.GetDstIpRange())
	}

	if r.GetSrcIpset() != "" {
		rule.SourceIp = r.GetSrcIpset()
	} else if r.GetSrcIp() != "" {
		rule.SourceIp = getRuleIpInfoFromIpTableRule(r.GetSrcIp())
	} else if r.GetSrcIpRange() != "" {
		rule.SourceIp = getRuleIpInfoFromIpTableRule(r.GetSrcIpRange())
	}

	rule.Protocol = strings.ToUpper(r.GetProto())
	rule.SourcePort = r.GetSrcPort()
	rule.DestPort = r.GetDstPort()
	rule.AllowStates = strings.Join(r.GetState(), ",")
	rule.AllowStates = strings.ToLower(rule.AllowStates)
	rule.Tcp = strings.Join(r.GetTcpFlags(), ",")
	rule.Icmp = r.GetIcmpType()
	rule.RuleNumber = r.GetRuleNumber()
	rule.EnableLog = false
	rule.State = "enable"
	rule.IsDefault = isDefaultRule(fmt.Sprintf("%d", rule.RuleNumber))

	return rule
}

func getRuleIpInfoFromIpTableRule(ip string) string {
	if strings.Contains(ip, "/32") {
		return strings.Split(ip, "/")[0]
	}
	return ip
}

func getIpTableRuleFromRule(ruleSetName string, r ruleInfo) *utils.IpTableRule {
	rule := utils.NewIpTableRule(ruleSetName)
	if strings.EqualFold(r.Action, utils.IPTABLES_ACTION_ACCEPT) {
		r.Action = utils.IPTABLES_ACTION_RETURN
	}
	rule.SetAction(strings.ToUpper(r.Action))
	/* all does not need be filled in iptables */
	if strings.ToLower(r.Protocol) != "all" {
		rule.SetProto(r.Protocol)
	}

	if r.DestPort != "" {
		rule.SetDstPort(strings.Replace(r.DestPort, "-", ":", -1))

	}

	if r.SourcePort != "" {
		rule.SetSrcPort(strings.Replace(r.SourcePort, "-", ":", -1))
	}

	if r.SourceIp != "" {
		if strings.ContainsAny(r.SourceIp, IP_SPLIT) {
			rule.SetSrcIpset(r.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX))
		} else if strings.Contains(r.SourceIp, "/") {
			rule.SetSrcIp(r.SourceIp)
		} else if strings.Contains(r.SourceIp, "-") {
			rule.SetSrcIpRange(r.SourceIp)
		} else {
			rule.SetSrcIp(r.SourceIp + "/32")
		}
	}
	if r.DestIp != "" {
		if strings.ContainsAny(r.DestIp, IP_SPLIT) {
			rule.SetDstIpset(r.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX))
		} else if strings.Contains(r.DestIp, "/") {
			rule.SetDstIp(r.DestIp)
		} else if strings.Contains(r.DestIp, "-") {
			rule.SetDstIpRange(r.DestIp)
		} else {
			rule.SetDstIp(r.DestIp + "/32")
		}
	}
	if r.AllowStates != "" {
		rule.SetState(strings.Split(strings.ToUpper(r.AllowStates), ","))
	}
	if r.Tcp != "" {
		rule.SetTcpFlags(strings.Split(strings.ToUpper(r.Tcp), ","))
	}

	rule.SetIcmpType(r.Icmp)
	utils.SetFirewallRuleNumber(rule, ruleSetName, r.RuleNumber)

	return rule
}

func getFirewallConfigFromIpTables(nics []ethInfo) []ethRuleSetRef {
	table := utils.NewIpTables(utils.FirewallTable)

	nicMap := make(map[string]ethInfo)
	for _, k := range nics {
		nicMap[k.Name] = k
	}

	var refs []ethRuleSetRef
	ruleSets := getRuleSetFromIpTable(table)

	for _, rset := range ruleSets {
		var ref ethRuleSetRef
		for _, nic := range nics {
			if strings.Contains(rset.Name, nic.Name) {
				items := strings.Split(rset.Name, ".")
				ref.Forward = items[len(items)-1]
				ref.RuleSetInfo = *rset
				ref.Mac = nic.Mac

				refs = append(refs, ref)
			}
		}
	}

	return refs
}

func createRuleSetByIptables(ruleSetName ruleSetInfo) {
	utils.PanicOnError(fmt.Errorf("this api is not supported"))
}

func deleteRuleSetByIptables(ruleSet string) {
	utils.PanicOnError(fmt.Errorf("this api is not supported"))
}

func attachRuleSetOnInterfaceByIptables(ref ethRuleSetRef) error {
	table := utils.NewIpTables(utils.FirewallTable)
	var rules []*utils.IpTableRule

	nicName, err := utils.GetNicNameByMac(ref.Mac)
	utils.PanicOnError(err)
	ruleSetName := buildRuleSetName(nicName, ref.Forward)

	table.AddChain(ruleSetName)

	/* attach ruleset to interface */
	if ref.Forward == FIREWALL_DIRECTION_OUT {
		rule := utils.NewIpTableRule(utils.VYOS_FWD_OUT_ROOT_CHAIN)
		rule.SetAction(ruleSetName)
		rule.SetOutNic(nicName)
		rules = append(rules, rule)
	} else if ref.Forward == FIREWALL_DIRECTION_IN {
		rule := utils.NewIpTableRule(utils.VYOS_FWD_ROOT_CHAIN)
		rule.SetAction(ruleSetName)
		rule.SetInNic(nicName)
		rules = append(rules, rule)
	} // local will not be updated

	rule := utils.NewDefaultIpTableRule(ruleSetName, utils.IPTABLES_RULENUMBER_MAX)
	rule.SetAction(getIptablesRuleActionFromRuleAction(ref.RuleSetInfo.ActionType))
	rules = append(rules, rule)

	table.AddIpTableRules(rules)

	return table.Apply()
}

func detachRuleSetOnInterfaceByIptables(nicName, forward string) {
	utils.PanicOnError(fmt.Errorf("this api is not supported"))
}

func getDefaultRule(ruleSetName string) bool {
	table := utils.NewIpTables(utils.FirewallTable)
	for _, r := range table.Rules {
		if r.GetChainName() != ruleSetName {
			continue
		}

		if utils.IsDefaultRule(r) {
			return true
		}
	}
	return false
}

func updateRuleSetByIptables(ruleSetName, defaultAction string) error {
	table := utils.NewIpTables(utils.FirewallTable)
	var rules []*utils.IpTableRule

	for _, r := range table.Rules {
		if r.GetChainName() != ruleSetName {
			continue
		}

		if utils.IsDefaultRule(r) {
			r.SetAction(getIptablesRuleActionFromRuleAction(defaultAction))
		}
	}

	// add default rule for chain out if not exist when change rule default action
	if !getDefaultRule(ruleSetName) {
		rule := utils.NewDefaultIpTableRule(ruleSetName, utils.IPTABLES_RULENUMBER_MAX)
		rule.SetAction(getIptablesRuleActionFromRuleAction(defaultAction))
		rules = append(rules, rule)
	}
	table.AddIpTableRules(rules)
	return table.Apply()
}

func createRuleByIptables(nicName, ruleSetName string, ref ethRuleSetRef) error {
	var rules []*utils.IpTableRule
	var oldRules []*utils.IpTableRule

	table := utils.NewIpTables(utils.FirewallTable)
	newIpsets := make(map[string]*utils.IpSet)
	deleteIpsets := make(map[string]*utils.IpSet)

	/* attach ruleset to interface */
	if ref.Forward == FIREWALL_DIRECTION_OUT {
		rule := utils.NewIpTableRule(utils.VYOS_FWD_OUT_ROOT_CHAIN)
		rule.SetAction(ruleSetName)
		rule.SetOutNic(nicName)
		rules = append(rules, rule)
	} else if ref.Forward == FIREWALL_DIRECTION_IN {
		rule := utils.NewIpTableRule(utils.VYOS_FWD_ROOT_CHAIN)
		rule.SetAction(ruleSetName)
		rule.SetInNic(nicName)
		rules = append(rules, rule)
	} // local will not be updated

	// add default rule for chain out if not exist when add a rule on chain out
	if ref.Forward == FIREWALL_DIRECTION_OUT {
		if !getDefaultRule(ruleSetName) {
			rule := utils.NewDefaultIpTableRule(ruleSetName, utils.IPTABLES_RULENUMBER_MAX)
			rule.SetAction(utils.IPTABLES_ACTION_RETURN)
			rules = append(rules, rule)
		}
	}

	for _, r := range ref.RuleSetInfo.Rules {
		srcSetName := r.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX)
		if r.SourceIp != "" && strings.ContainsAny(r.SourceIp, IP_SPLIT) {
			srcIpSet := createIpsetAndSetNet(srcSetName, r.SourceIp)
			if srcIpSet == nil {
				goto ERROR_OUT
			}
			newIpsets[srcIpSet.Name] = srcIpSet
		} else {
			delIpSet := utils.NewIPSet(srcSetName, utils.IPSET_TYPE_HASH_NET)
			deleteIpsets[delIpSet.Name] = delIpSet
		}

		dstSetName := r.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX)
		if r.DestIp != "" && strings.ContainsAny(r.DestIp, IP_SPLIT) {
			dstIpSet := createIpsetAndSetNet(dstSetName, r.DestIp)
			if dstIpSet == nil {
				goto ERROR_OUT
			}
			newIpsets[dstIpSet.Name] = dstIpSet
		} else {
			delIpSet := utils.NewIPSet(dstSetName, utils.IPSET_TYPE_HASH_NET)
			deleteIpsets[delIpSet.Name] = delIpSet
		}

		rule := getIpTableRuleFromRule(ruleSetName, r)
		for _, oldRule := range utils.GetFirewallIpTableRule(table) {
			if strings.Contains(oldRule.GetComment(), rule.GetComment()) {
				oldRules = append(oldRules, oldRule)
			}
		}
		if r.EnableLog {
			rule1 := *rule
			rule1.SetAction(utils.IPTABLES_ACTION_LOG)
			rules = append(rules, &rule1)
		}
		if r.State == RULEINFO_ENABLE {
			rules = append(rules, rule)
		}
	}

	removeIptablesRulesByFirewallRuleNumber(table, oldRules, true)
	table.AddIpTableRules(rules)
	if err := table.Apply(); err != nil {
		deleteIpsetMap(newIpsets)
		return err
	}
	if err := swapIpsetAndDeleteTmp(newIpsets); err != nil {
		return err
	}
	deleteIpsetMap(deleteIpsets)

	return nil

ERROR_OUT:
	deleteIpsetMap(newIpsets)
	return fmt.Errorf("createRuleByIptables: createIpsetAndSetNet error")
}

func deleteRuleByIpTables(ruleSetName string, ref ethRuleSetRef) error {
	var rules []*utils.IpTableRule

	table := utils.NewIpTables(utils.FirewallTable)
	deleteIpsets := make(map[string]*utils.IpSet)

	for _, r := range ref.RuleSetInfo.Rules {
		rules = append(rules, getIpTableRuleFromRule(ruleSetName, r))
	}
	//table.RemoveIpTableRule(rules)
	removeIptablesRulesByFirewallRuleNumber(table, rules, true)
	if err := table.Apply(); err != nil {
		return err
	}

	for _, r := range ref.RuleSetInfo.Rules {
		if r.SourceIp != "" && strings.ContainsAny(r.SourceIp, IP_SPLIT) {
			srcSetName := r.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX)
			srcSet := utils.NewIPSet(srcSetName, utils.IPSET_TYPE_HASH_NET)
			deleteIpsets[srcSetName] = srcSet
		}

		if r.DestIp != "" && strings.ContainsAny(r.DestIp, IP_SPLIT) {
			dstSetName := r.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX)
			dstSet := utils.NewIPSet(dstSetName, utils.IPSET_TYPE_HASH_NET)
			deleteIpsets[dstSetName] = dstSet
		}
	}

	deleteIpsetMap(deleteIpsets)

	return nil
}

func changeRuleStateByIpTables(ruleSetName string, r ruleInfo, state string) error {
	table := utils.NewIpTables(utils.FirewallTable)

	rule := getIpTableRuleFromRule(ruleSetName, r)
	if state == "disable" {
		table.RemoveIpTableRule([]*utils.IpTableRule{rule})
	} else {
		table.AddIpTableRules([]*utils.IpTableRule{rule})
	}

	return table.Apply()
}

func applyRuleSetChangesByIpTables(cmd *applyRuleSetChangesCmd) error {
	var addRules []*utils.IpTableRule
	var deleteRules []*utils.IpTableRule

	table := utils.NewIpTables(utils.FirewallTable)
	deleteIpsets := make(map[string]*utils.IpSet)
	newIpsets := make(map[string]*utils.IpSet)

	/*
	   if origin ruleinfo state is enable, new ruleinfo state is disable,will delete origin iptables rule, not create new iptables rule
	   if origin ruleinfo state is disable, new ruleinfo state is enable,will create new iptables rule
	*/
	cmd.NewRules = deleteDisableRuleInfo(cmd.NewRules)
	for _, ref := range cmd.Refs {
		nic, err := utils.GetNicNameByMac(ref.Mac)
		utils.PanicOnError(err)
		ruleSetName := buildRuleSetName(nic, ref.Forward)
		for _, rule := range cmd.DeleteRules {
			if rule.SourceIp != "" && strings.ContainsAny(rule.SourceIp, IP_SPLIT) {
				srcSetName := rule.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX)
				srcSet := utils.NewIPSet(srcSetName, utils.IPSET_TYPE_HASH_NET)
				deleteIpsets[srcSetName] = srcSet
			}

			if rule.DestIp != "" && strings.ContainsAny(rule.DestIp, IP_SPLIT) {
				dstSetName := rule.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX)
				dstSet := utils.NewIPSet(dstSetName, utils.IPSET_TYPE_HASH_NET)
				deleteIpsets[dstSetName] = dstSet
			}

			deleteRules = append(deleteRules, getIpTableRuleFromRule(ruleSetName, rule))
		}

		for _, rule := range cmd.NewRules {
			if rule.SourceIp != "" && strings.ContainsAny(rule.SourceIp, IP_SPLIT) {
				srcSetName := rule.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX)
				newIpSet := createIpsetAndSetNet(srcSetName, rule.SourceIp)
				if newIpSet == nil {
					goto ERROR_OUT
				}
				newIpsets[newIpSet.Name] = newIpSet
			}
			if rule.DestIp != "" && strings.ContainsAny(rule.DestIp, IP_SPLIT) {
				dstSetName := rule.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX)
				newIpSet := createIpsetAndSetNet(dstSetName, rule.DestIp)
				if newIpSet == nil {
					goto ERROR_OUT
				}
				newIpsets[newIpSet.Name] = newIpSet
			}

			addRules = append(addRules, getIpTableRuleFromRule(ruleSetName, rule))
		}
	}

	table = removeIptablesRulesByFirewallRuleNumber(table, deleteRules, true)
	table.AddIpTableRules(addRules)

	if err := table.Apply(); err != nil {
		deleteIpsetMap(newIpsets)
		return err
	}

	deleteIpsetMap(deleteIpsets)
	if err := swapIpsetAndDeleteTmp(newIpsets); err != nil {
		return err
	}

	return nil

ERROR_OUT:
	deleteIpsetMap(newIpsets)
	return fmt.Errorf("applyRuleSetChangesByIpTables: createIpsetAndSetNet error")
}

func applyUserRulesByIpTables(cmd *applyUserRuleCmd) error {
	var rules []*utils.IpTableRule
	table := utils.NewIpTables(utils.FirewallTable)
	newIpsets := make(map[string]*utils.IpSet)

	//if apply firewall Rule, delete all firewall rule first
	table = deleteFirewallUserRule(table)
	for _, ref := range cmd.Refs {
		nicName, err := utils.GetNicNameByMac(ref.Mac)
		utils.PanicOnError(err)
		ruleSetName := buildRuleSetName(nicName, ref.Forward)

		//create ruleSet and add last rule
		table.AddChain(ruleSetName)
		rule := utils.NewDefaultIpTableRule(ruleSetName, utils.IPTABLES_RULENUMBER_MAX)
		rule.SetAction(getIptablesRuleActionFromRuleAction(ref.RuleSetInfo.ActionType))
		rules = append(rules, rule)

		/* attach ruleset to interface */
		if ref.Forward == FIREWALL_DIRECTION_OUT {
			rule := utils.NewIpTableRule(utils.VYOS_FWD_OUT_ROOT_CHAIN)
			rule.SetAction(ruleSetName)
			rule.SetOutNic(nicName)
			rules = append(rules, rule)
		} else if ref.Forward == FIREWALL_DIRECTION_IN {
			rule := utils.NewIpTableRule(utils.VYOS_FWD_ROOT_CHAIN)
			rule.SetAction(ruleSetName)
			rule.SetOutNic(nicName)
			rules = append(rules, rule)
		} // local will not be updated

		// if ruleInfo state is disable, not create iptables rule
		ref.RuleSetInfo.Rules = deleteDisableRuleInfo(ref.RuleSetInfo.Rules)
		for _, r := range ref.RuleSetInfo.Rules {
			if r.SourceIp != "" && strings.ContainsAny(r.SourceIp, IP_SPLIT) {
				srcSetName := r.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX)
				newIpSet := createIpsetAndSetNet(srcSetName, r.SourceIp)
				if newIpSet == nil {
					goto ERROR_OUT
				}
				newIpsets[newIpSet.Name] = newIpSet
			}
			if r.DestIp != "" && strings.ContainsAny(r.DestIp, IP_SPLIT) {
				dstSetName := r.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX)
				newIpSet := createIpsetAndSetNet(dstSetName, r.DestIp)
				if newIpSet == nil {
					goto ERROR_OUT
				}
				newIpsets[newIpSet.Name] = newIpSet
			}

			rule := getIpTableRuleFromRule(ruleSetName, r)
			if r.EnableLog {
				rule1 := rule.Copy()
				rule1.SetAction(utils.IPTABLES_ACTION_LOG)
				rules = append(rules, rule1)
			}
			rules = append(rules, rule)
		}
	}

	table.AddIpTableRules(rules)

	if err := table.Apply(); err != nil {
		deleteIpsetMap(newIpsets)
		return err
	}
	if err := swapIpsetAndDeleteTmp(newIpsets); err != nil {
		return err
	}

	return nil

ERROR_OUT:
	deleteIpsetMap(newIpsets)
	return fmt.Errorf("applyUserRulesByIpTables: createIpsetAndSetNet error")
}

/* 1 vpc router only has 1 vpc firewall */
func deleteUserRuleByIpTables(cmd *getConfigCmd) error {
	table := utils.NewIpTables(utils.FirewallTable)
	table = deleteFirewallUserRule(table)
	/* only public nic has rule number: 9999 */
	nics := utils.GetBootStrapNicInfo()
	for _, nic := range nics {
		if nic.Catatory == "Private" {
			continue
		}

		rulesetName := buildRuleSetName(nic.Name, FIREWALL_DIRECTION_IN)
		rule := utils.NewDefaultIpTableRule(rulesetName, utils.IPTABLES_RULENUMBER_9999)
		rule.SetAction(utils.IPTABLES_ACTION_RETURN)
		table.AddIpTableRules([]*utils.IpTableRule{rule})
	}

	/* only delete chain out's default rule with number: 10000 */
	for _, nic := range nics {
		rulesetName := buildRuleSetName(nic.Name, FIREWALL_DIRECTION_OUT)
		if getDefaultRule(rulesetName) {
			rule := utils.NewDefaultIpTableRule(rulesetName, utils.IPTABLES_RULENUMBER_MAX)
			removeIptablesRulesByFirewallRuleNumber(table, []*utils.IpTableRule{rule}, false)
		}
	}
	return table.Apply()
}

/* 1 vpc router only has 1 vpc firewall */
func deleteFirewallUserRule(table *utils.IpTables) *utils.IpTables {
	rules := utils.GetFirewallIpTableRule(table)
	removeIptablesRulesByFirewallRuleNumber(table, rules, true)

	for _, r := range rules {
		if r.GetSrcIpset() != "" {
			srcSet := utils.NewIPSet(r.GetSrcIpset(), utils.IPSET_TYPE_HASH_NET)
			srcSet.Destroy()
		}

		if r.GetDstIpset() != "" {
			dstSet := utils.NewIPSet(r.GetDstIpset(), utils.IPSET_TYPE_HASH_NET)
			dstSet.Destroy()
		}
	}

	return table
}

func deleteDisableRuleInfo(ruleInfos []ruleInfo) []ruleInfo {
	ruleInfoEnable := make([]ruleInfo, 0)
	for _, rInfo := range ruleInfos {
		if rInfo.State == RULEINFO_ENABLE {
			ruleInfoEnable = append(ruleInfoEnable, rInfo)
		}
	}
	return ruleInfoEnable
}

func getIptablesRuleActionFromRuleAction(action string) string {
	if strings.EqualFold(action, utils.IPTABLES_ACTION_ACCEPT) {
		return utils.IPTABLES_ACTION_RETURN
	}

	return strings.ToUpper(action)
}

func removeIptablesRulesByFirewallRuleNumber(tables *utils.IpTables, rules []*utils.IpTableRule, ignoreDefaultRule bool) *utils.IpTables {
	var newRules []*utils.IpTableRule
	for _, nr := range tables.Rules {
		if !strings.Contains(nr.GetComment(), utils.FirewallRule) && ignoreDefaultRule {
			newRules = append(newRules, nr)
			continue
		}
		found := false
		for _, r := range rules {
			if nr.GetChainName() != r.GetChainName() {
				continue
			}

			if r.GetRuleNumber() == nr.GetRuleNumber() {
				found = true
				break
			}
		}

		if !found {
			newRules = append(newRules, nr)
		}
	}

	tables.Rules = newRules
	return tables
}

func swapIpsetAndDeleteTmp(ipSetMap map[string]*utils.IpSet) error {
	for name, tmpIpSet := range ipSetMap {
		if !strings.HasSuffix(name, "-tmp") {
			continue
		}
		oldIpset := utils.NewIPSet(strings.TrimSuffix(tmpIpSet.Name, "-tmp"), utils.IPSET_TYPE_HASH_NET)
		if !oldIpset.IsExist() {
			return fmt.Errorf("swapIpsetAndDeleteTmp: ipset %s doesn't exist", oldIpset.Name)
		}
		if !tmpIpSet.IsExist() {
			return fmt.Errorf("swapIpsetAndDeleteTmp: ipset %s doesn't exist", tmpIpSet.Name)
		}
		if !tmpIpSet.Swap(oldIpset) {
			tmpIpSet.Destroy()
			return fmt.Errorf("swapIpsetAndDeleteTmp: ipset swap from %s to %s error", tmpIpSet.Name, oldIpset.Name)
		}
		if err := tmpIpSet.Destroy(); err != nil {
			return fmt.Errorf("swapIpsetAndDeleteTmp: ipset destroy %s error", tmpIpSet.Name)
		}
	}

	return nil
}

func deleteIpsetMap(ipSetMap map[string]*utils.IpSet) error {
	for _, tmpIpSet := range ipSetMap {
		if tmpIpSet == nil {
			continue
		}
		if err := tmpIpSet.Destroy(); err != nil {
			log.Debugf("deleteIpsetMap: %s", err)
		}
	}

	return nil
}

func createIpsetAndSetNet(setName string, ipString string) *utils.IpSet {
	var newIpSet *utils.IpSet
	var ips []string

	if setName == "" || ipString == "" {
		return nil
	}
	newIpSet = utils.NewIPSet(setName, utils.IPSET_TYPE_HASH_NET)
	if newIpSet.IsExist() {
		newIpSet.Name = fmt.Sprintf("%s-tmp", setName)
	}

	if err := newIpSet.Create(); err != nil {
		return nil
	}

	ips = strings.Split(ipString, IP_SPLIT)
	if err := newIpSet.AddMember(ips); err != nil {
		goto ERROR_OUT
	}

	return newIpSet

ERROR_OUT:
	newIpSet.Destroy()
	return nil
}
