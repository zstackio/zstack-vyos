package plugin

import (
	"fmt"
	"zvr/server"
	"zvr/utils"
)

const (
	SYNC_POLICY_ROUTE = "/policyroute/sync"
)

type policyRuleSetInfo struct {
	RuleSetName string `json:"ruleSetName"`
}

type policyRuleInfo struct {
	RuleSetName string `json:"ruleSetName"`
	RuleNumber int `json:"ruleNumber"`
	DestPort string `json:"destPort"`
	Protocol string `json:"protocol"`
	SourcePort string `json:"sourcePort"`
	SourceIp string `json:"sourceIp"`
	DestIp string `json:"destIp"`
	State string `json:"state"`
	TableNumber int `json:"tableNumber"`
}

type policyRouteInfo struct {
	TableNumber int `json:"tableNumber"`
	DestinationCidr string `json:"destinationCidr"`
	NextHopIp string `json:"nextHopIp"`
	Distance int `json:"distance"`
}

type policyRuleSetNicRef struct {
	RuleSetName string `json:"ruleSetName"`
	Mac string `json:"mac"`
}

type syncPolicyRouteCmd struct {
	RuleSets []policyRuleSetInfo `json:"ruleSets"`
	Rules []policyRuleInfo `json:"rules"`
	TableNumbers []int `json:"tableNumbers"`
	Routes []policyRouteInfo `json:"routes"`
	Refs []policyRuleSetNicRef `json:"refs"`
}

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
}

func syncPolicyRoute(ctx *server.CommandContext) interface{} {
	cmd := &syncPolicyRouteCmd{}
	ctx.GetCommand(cmd)
	deletePolicyRoutes()
	applyPolicyRoutes(cmd)
	return nil
}

func PolicyRouteEntryPoint()  {
	server.RegisterAsyncCommandHandler(SYNC_POLICY_ROUTE, server.VyosLock(syncPolicyRoute))
}