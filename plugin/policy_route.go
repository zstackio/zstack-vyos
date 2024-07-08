package plugin

import (
	"fmt"
	"strings"
	"zstack-vyos/server"
	"zstack-vyos/utils"
)

const (
	SYNC_POLICY_ROUTE        = "/policyroute/sync"
	POLICY_ROUTE_TABLE_CHAIN = "zs-rt-"
)

type policyRuleSetInfo struct {
	RuleSetName string `json:"ruleSetName"`
	System      bool   `json:"system"`
}

type policyRuleInfo struct {
	RuleSetName string `json:"ruleSetName"`
	RuleNumber  int    `json:"ruleNumber"`
	DestPort    string `json:"destPort"`
	Protocol    string `json:"protocol"`
	SourcePort  string `json:"sourcePort"`
	SourceIp    string `json:"sourceIp"`
	DestIp      string `json:"destIp"`
	State       string `json:"state"`
	TableNumber int    `json:"tableNumber"`
}

type policyRouteInfo struct {
	TableNumber     int    `json:"tableNumber"`
	DestinationCidr string `json:"destinationCidr"`
	NextHopIp       string `json:"nextHopIp"`
	OutNicMic       string `json:"outNicMic"`
	Distance        int    `json:"distance"`
}

type policyRuleSetNicRef struct {
	RuleSetName string `json:"ruleSetName"`
	Mac         string `json:"mac"`
}

type syncPolicyRouteCmd struct {
	RuleSets      []policyRuleSetInfo   `json:"ruleSets"`
	Rules         []policyRuleInfo      `json:"rules"`
	TableNumbers  []int                 `json:"tableNumbers"`
	Routes        []policyRouteInfo     `json:"routes"`
	Refs          []policyRuleSetNicRef `json:"refs"`
	MarkConntrack bool                  `json:"markConntrack"`
}

/*
func (r *policyRuleInfo) toRules() []string {
	rules := make([]string, 0)
	if r.State == "disable" {
		rules = append(rules, fmt.Sprintf("disable"))
	}
	if r.SourcePort != "" {
		rules = append(rules, fmt.Sprintf("source port %s", r.SourcePort))
	}
	if r.DestPort != "" {
		rules = append(rules, fmt.Sprintf("destination port %s", r.DestPort))
	}
	if r.DestIp != "" {
		rules = append(rules, fmt.Sprintf("destination address %s", r.DestIp))
	}
	if r.SourceIp != "" {
		rules = append(rules, fmt.Sprintf("source address %s", r.SourceIp))
	}
	if r.TableNumber != 0 {
		rules = append(rules, fmt.Sprintf("set table %v", r.TableNumber))
	}
	if r.Protocol != "" {
		rules = append(rules, fmt.Sprintf("protocol %s", r.Protocol))
	}

	return rules
}

func deletePolicyRoutes() {
	//detach policy ruleSet
	tree := server.NewParserFromShowConfiguration().Tree
	if nics, nicErr := utils.GetAllNics(); nicErr == nil {
		for _, val := range nics {
			if nicNode := tree.Get(fmt.Sprintf("interfaces ethernet %s policy route", val.Name)); nicNode != nil {
				nicNode.Delete()
			}
		}
	}

	tree.Apply(false)

	//delete policy ruleSet
	if rs := tree.Get("policy route"); rs != nil {
		if ruleSetNodes := rs.Children(); ruleSetNodes != nil {
			for _, rsNode := range ruleSetNodes {
				rsNode.Delete()
			}
		}
	}

	//delete policy route table
	if rt := tree.Get("protocols static table"); rt != nil {
		if tableNodes := rt.Children(); tableNodes != nil {
			for _, tableNode := range tableNodes {
				tableNode.Delete()
			}
		}
	}

	tree.Apply(false)
}

func applyPolicyRoutes(cmd *syncPolicyRouteCmd) {
	tree := server.NewParserFromShowConfiguration().Tree
	for _, ruleSet := range cmd.RuleSets {
		tree.CreatePolicyRouteRuleSet(ruleSet.RuleSetName)
	}
	for _, rule := range cmd.Rules {
		tree.CreatePolicyRouteRule(rule.RuleSetName, rule.RuleNumber, rule.toRules())
	}
	for _, tableNumber := range cmd.TableNumbers {
		tree.CreatePolicyRouteTable(tableNumber)
	}
	for _, route := range cmd.Routes {
		tree.CreatePolicyRoute(route.TableNumber, route.DestinationCidr, route.NextHopIp, route.Distance)
	}
	for _, ref := range cmd.Refs {
		nic, err := utils.GetNicNameByMac(ref.Mac); utils.PanicOnError(err)
		tree.AttachPolicyRuleSetToNic(nic, ref.RuleSetName)
	}
	tree.Apply(false)
}*/

func getPolicyRouteSetChainName(rulesetName string) string {
	return fmt.Sprintf("%s%s", utils.PolicyRouteRuleChainPrefix, rulesetName)
}

func getPolicyRouteTableChainName(tableId int) string {
	return fmt.Sprintf("%s%d", utils.PolicyRouteChainPrefix, tableId)
}

func getPolicyRouteTableChainNameByString(tableId string) string {
	return fmt.Sprintf("%s%s", utils.PolicyRouteChainPrefix, tableId)
}

func syncPolicyRoute(ctx *server.CommandContext) interface{} {
	cmd := &syncPolicyRouteCmd{}
	ctx.GetCommand(cmd)
	applyPolicyRoutes(cmd)
	return nil
}

func applyPolicyRoutes(cmd *syncPolicyRouteCmd) {
	var rts []utils.ZStackRouteTable
	var ipRules []utils.ZStackIpRule
	currRules := utils.GetZStackIpRules()
	currTables := utils.GetZStackRouteTables()
	for _, rt := range cmd.TableNumbers {
		rts = append(rts, utils.ZStackRouteTable{TableId: rt,
			Alias: fmt.Sprintf("%s%d", utils.PolicyRouteChainPrefix, rt)})
		ipRules = append(ipRules, utils.ZStackIpRule{Fwmark: uint64(rt), TableId: rt})
	}

	entriesMap := map[int][]utils.ZStackRouteEntry{}
	for _, route := range cmd.Routes {
		if route.OutNicMic != "" {
			nicName, err := utils.GetNicNameByMac(route.OutNicMic)
			utils.PanicOnError(err)
			if _, ok := entriesMap[route.TableNumber]; !ok {
				entriesMap[route.TableNumber] = []utils.ZStackRouteEntry{}
			}
			entriesMap[route.TableNumber] = append(entriesMap[route.TableNumber], utils.ZStackRouteEntry{TableId: route.TableNumber, DestinationCidr: route.DestinationCidr,
				NextHopIp: route.NextHopIp, NicName: nicName, Distance: route.Distance})
		} else {
			if _, ok := entriesMap[route.TableNumber]; !ok {
				entriesMap[route.TableNumber] = []utils.ZStackRouteEntry{}
			}
			entriesMap[route.TableNumber] = append(entriesMap[route.TableNumber], utils.ZStackRouteEntry{TableId: route.TableNumber, DestinationCidr: route.DestinationCidr,
				NextHopIp: route.NextHopIp, NicName: "", Distance: route.Distance})
		}
	}

	var rules []*utils.IpTableRule
	mangleTable := utils.NewIpTables(utils.MangleTable)
	mangleTable.RemoveIpTableRuleByComments(utils.PolicyRouteComment)
	// delete residual iptables rules when upgrade
	mangleTable.RemoveIpTableRuleByComments("Zs-Pr-Rules")

	if len(cmd.RuleSets) > 0 && cmd.MarkConntrack {
		rule := utils.NewIpTableRule(utils.PREROUTING.String())
		rule.SetAction(utils.IPTABLES_ACTION_CONNMARK_RESTORE).SetComment(utils.PolicyRouteComment)
		rule.SetMarkType(utils.IptablesMarkUnset)
		rules = append(rules, rule)

		rule = utils.NewIpTableRule(utils.PREROUTING.String())
		rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(utils.PolicyRouteComment)
		rule.SetMarkType(utils.IptablesMarkNotMatch)
		rules = append(rules, rule)
	}

	for _, table := range cmd.TableNumbers {
		chainName := getPolicyRouteTableChainName(table)
		mangleTable.AddChain(chainName)

		rule := utils.NewIpTableRule(chainName)
		rule.SetAction(utils.IPTABLES_ACTION_MARK).SetTargetMark(table)
		rule.SetComment(utils.PolicyRouteComment).SetMarkType(utils.IptablesMarkMatch).SetMark(0)
		rules = append(rules, rule)

		if cmd.MarkConntrack {
			rule := utils.NewIpTableRule(chainName)
			rule.SetAction(utils.IPTABLES_ACTION_CONNMARK).SetTargetMark(table)
			rule.SetComment(utils.PolicyRouteComment)
			rules = append(rules, rule)
		}
	}

	systemRuleSetMap := map[string]bool{}
	for _, rset := range cmd.RuleSets {
		systemRuleSetMap[rset.RuleSetName] = rset.System
		chainName := getPolicyRouteSetChainName(rset.RuleSetName)
		mangleTable.AddChain(chainName)
	}

	for _, ref := range cmd.Refs {
		nicname, err := utils.GetNicNameByMac(ref.Mac)
		utils.PanicOnError(err)
		chainName := getPolicyRouteSetChainName(ref.RuleSetName)
		rule := utils.NewIpTableRule(utils.PREROUTING.String())
		rule.SetAction(chainName).SetComment(utils.PolicyRouteComment)
		rule.SetMarkType(utils.IptablesMarkUnset).SetMark(0).SetInNic(nicname)
		rules = append(rules, rule)

		if systemRuleSetMap[ref.RuleSetName] {
			items := strings.Split(ref.RuleSetName, "-")
			routeTableChainName := getPolicyRouteTableChainNameByString(items[len(items)-1])
			rule := utils.NewIpTableRule(chainName)
			rule.SetAction(routeTableChainName).SetComment(utils.PolicyRouteComment)
			rule.SetMarkType(utils.IptablesMarkUnset).SetMark(0)
			rules = append(rules, rule)
		}
	}

	for _, r := range cmd.Rules {
		if r.State == "disable" {
			continue
		}

		if systemRuleSetMap[r.RuleSetName] {
			ipRules = append(ipRules, utils.ZStackIpRule{From: r.SourceIp, TableId: r.TableNumber})
			continue
		}

		chainName := getPolicyRouteSetChainName(r.RuleSetName)
		rule := utils.NewIpTableRule(chainName)
		rule.SetAction(getPolicyRouteTableChainName(r.TableNumber)).SetComment(utils.PolicyRouteComment)
		rule.SetProto(r.Protocol).SetSrcPort(r.SourcePort).SetDstPort(r.DestPort)
		if r.SourceIp != "" {
			if strings.Contains(r.SourceIp, "/") {
				rule.SetSrcIp(r.SourceIp)
			} else {
				rule.SetSrcIp(r.SourceIp + "/32")
			}

		}
		if r.DestIp != "" {
			if strings.Contains(r.DestIp, "/") {
				rule.SetDstIp(r.DestIp)
			} else {
				rule.SetDstIp(r.DestIp + "/32")
			}
		}
		rule.SetMarkType(utils.IptablesMarkUnset).SetMark(0)
		rules = append(rules, rule)
	}

	err := utils.SyncZStackRouteTables(rts)
	utils.PanicOnError(err)
	err = utils.SyncZStackIpRules(currRules, ipRules)
	utils.PanicOnError(err)
	if err = utils.SyncRouteEntries(currTables, entriesMap); err != nil && IsMaster() {
		utils.PanicOnError(err)
	}
	mangleTable.AddIpTableRules(rules)
	err = mangleTable.Apply()
	utils.PanicOnError(err)
}

func PolicyRouteEntryPoint() {
	server.RegisterAsyncCommandHandler(SYNC_POLICY_ROUTE, server.VyosLock(syncPolicyRoute))
}
