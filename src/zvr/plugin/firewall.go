package plugin

import (
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"strconv"
	"strings"
	"zvr/server"
	"zvr/utils"
)

const (
	fwGetConfigPath = "/fw/getConfig"
	fwCreateRulePath = "/fw/create/rule"
	fwDeleteRulePath = "/fw/delete/rule"
	fwChangeRuleStatePath = "/fw/changeState/rule"
	fwCreateRuleSetPath = "/fw/create/ruleSet"
	fwDeleteRuleSetPath = "/fw/delete/ruleSet"
	fwAttachRulesetPath = "/fw/attach/ruleSet"
	fwDetachRuleSetPath = "/fw/detach/ruleSet"
	fwApplyUserRulesPath = "/fw/apply/rule"
	fwUpdateRuleSetPath = "/fw/update/ruleSet"
	fwDeleteUserRulePath = "/fw/delete/firewall"
	zstackRuleNumberFront = 1000
	zstackRuleNumberEnd = 4000
	USER_RULE_SET_PREFIX = "ZS-FW-RS"
)

type ethInfo struct {
	Name string `json:"name"`
	Mac string `json:"mac"`
}

type ruleInfo struct {
	RuleSetName string `json:"ruleSetName"`
	Action string `json:"action"`
	Protocol string `json:"protocol"`
	DestPort string `json:"destPort"`
	SourcePort string `json:"sourcePort"`
	SourceIp string `json:"sourceIp"`
	DestIp string `json:"destIp"`
	AllowStates string `json:"allowStates"`
	Tcp string `json:"tcp"`
	Icmp string `json:"icmp"`
	RuleNumber int `json:"ruleNumber"`
	EnableLog bool `json:"enableLog"`
	State string `json:"state"`
	IsDefault bool `json:"isDefault"`
}

type ethRuleSetRef struct {
	EthName string `json:"ethName"`
	RuleSetName string `json:"ruleSetName"`
	Forward string `json:"forward"`
}

type ruleSetInfo struct {
	Name string `json:"name"`
	ActionType string `json:"actionType"`
	EnableDefaultLog bool `json:"enableDefaultLog"`
}

type defaultRuleSetAction struct {
	RuleSetName string `json:"ruleSetName"`
	ActionType string `json:"actionType"`
}

type getConfigCmd struct {
	Macs []string `json:"macs"`
}

type getConfigRsp struct {
	RuleSets []ruleSetInfo `json:"ruleSets"`
	Rules []ruleInfo `json:"rules"`
	Refs []ethRuleSetRef `json:"refs"`
	Interfaces []ethInfo `json:"interfaces"`
}

type applyUserRuleCmd struct {
	RuleSets []ruleSetInfo `json:"ruleSets"`
	Rules []ruleInfo `json:"rules"`
	Refs []ethRuleSetRef `json:"refs"`
	DefaultRuleSetActions []defaultRuleSetAction `json:"defaultRuleSetActions"`
}

type createRuleCmd struct {
	Rule ruleInfo `json:"rule"`
}

type changeRuleStateCmd struct {
	Rule ruleInfo `json:"rule"`
	State string `json:"state"`
}

type deleteRuleCmd struct {
	Rule ruleInfo `json:"rule"`
}

type deleteRuleSetCmd struct {
	RuleSetName string `json:"ruleSetName"`
}

type createRuleSetCmd struct {
	RuleSet ruleSetInfo `json:"ruleSet"`
}

type attachRuleSetCmd struct {
	Ref ethRuleSetRef `json:"ref"`
}

type detachRuleSetCmd struct {
	Ref ethRuleSetRef `json:"ref"`
}

type updateRuleSetCmd struct {
	Name string `json:"ruleSetName"`
	ActionType string `json:"actionType"`
}

func (r *ruleSetInfo) toRules() []string {
	rules := make([]string, 0)
	if r.ActionType != "" {
		rules = append(rules, fmt.Sprintf("default-action %s", r.ActionType))
	}
	if r.EnableDefaultLog {
		rules = append(rules, "enable-default-log")
	}

	return rules
}

func (r *ruleInfo) toRules() []string {
	rules := make([]string, 0)
	if r.Action != "" {
		rules = append(rules, fmt.Sprintf("action %s",r.Action))
	}
	if r.Protocol != "" {
		rules = append(rules, fmt.Sprintf("protocol %s",r.Protocol))
	}
	if r.Tcp != "" {
		rules = append(rules, fmt.Sprintf("tcp flags %s",r.Tcp))
	}
	if r.Icmp != "" {
		rules = append(rules, fmt.Sprintf("icmp type-name %s",r.Icmp))
	}
	if r.EnableLog {
		rules = append(rules, fmt.Sprintf("log enable"))
	}
	if r.State == "disable" {
		rules = append(rules, fmt.Sprintf("disable"))
	}
	if r.SourcePort != "" {
		rules = append(rules, fmt.Sprintf("source port %s",r.SourcePort))
	}
	if r.DestPort != "" {
		rules = append(rules, fmt.Sprintf("destination port %s",r.DestPort))
	}
	if r.DestIp != "" {
		rules = append(rules, fmt.Sprintf("destination address %s",r.DestIp))
	}
	if r.SourceIp != "" {
		rules = append(rules, fmt.Sprintf("source address %s",r.SourceIp))
	}
	if r.AllowStates != "" {
		for _,state := range strings.Split(r.AllowStates, ",") {
			rules = append(rules, fmt.Sprintf("state %s enable",state))
		}
	}
	return rules
}

func getIp(t *server.VyosConfigNode, forward string) string {
	if forward != "destination" && forward != "source" {
		panic(fmt.Sprintf("the forward can only be [destination, source], but %s get", forward))
	}
	if ip := t.GetChildrenValue(fmt.Sprintf("%s address", forward)); ip != "" {
		return ip
	} else {
		return t.GetChildrenValue(fmt.Sprintf("%s address group address-group",forward))
	}
}

func isDefaultRule(n string) bool {
	number, _ := strconv.Atoi(n)
	if number <= zstackRuleNumberFront || number >= zstackRuleNumberEnd {
		return true
	} else {
		return false
	}
}


func getRuleNumber(t *server.VyosConfigNode) int {
	number, err := strconv.Atoi(t.Name())
	if err == nil {
		return number
	}
	panic(fmt.Errorf("get rule number failed on node[%s]", t))
}

func getRuleState(t *server.VyosConfigNode) string {
	if t.Get("disable") != nil {
		return "disable"
	} else {
		return "enable"
	}
}

func getAllowStates(t *server.VyosConfigNode) string {
	if d := t.Get("state"); d == nil || len(d.Children()) == 0 {
		return ""
	} else {
		states := make([]string,0)
		for _, c := range d.Children() {
			if c.Value() == "enable" {
				states = append(states, c.Name())
			}
		}

		return strings.Join(states, ",")
	}
}

func detachRuleSet(ctx *server.CommandContext) interface{} {
	cmd := &detachRuleSetCmd{}
	ctx.GetCommand(cmd)
	ref := cmd.Ref
	tree := server.NewParserFromShowConfiguration().Tree
	tree.Deletef("interfaces ethernet %s firewall %s", ref.EthName, ref.Forward)
	tree.Apply(false)
	return nil
}

func attachRuleSet(ctx *server.CommandContext) interface{} {
	cmd := &attachRuleSetCmd{}
	ctx.GetCommand(cmd)
	ref := cmd.Ref
	tree := server.NewParserFromShowConfiguration().Tree
	tree.AttachRuleSetOnInterface(ref.EthName, ref.Forward, ref.RuleSetName)
	tree.Apply(false)
	return nil
}

func deleteRuleSet(ctx *server.CommandContext) interface{} {
	cmd := &deleteRuleSetCmd{}
	ctx.GetCommand(cmd)
	tree := server.NewParserFromShowConfiguration().Tree
	tree.Deletef("firewall name %s", cmd.RuleSetName)
	tree.Apply(false)
	return nil
}

func createRuleSet(ctx *server.CommandContext) interface{} {
	cmd := &createRuleSetCmd{}
	ctx.GetCommand(cmd)
	tree := server.NewParserFromShowConfiguration().Tree
	ruleSet := cmd.RuleSet
	tree.CreateFirewallRuleSet(ruleSet.Name, ruleSet.toRules())
	tree.Apply(false)
	return nil
}

func deleteRule(ctx *server.CommandContext) interface{} {
	cmd := &deleteRuleCmd{}
	ctx.GetCommand(cmd)
	rule := cmd.Rule
	tree := server.NewParserFromShowConfiguration().Tree
	tree.Deletef("firewall name %s rule %v", rule.RuleSetName, rule.RuleNumber)
	tree.Apply(false)
	return nil
}

func createRule(ctx *server.CommandContext) interface{} {
	cmd := &createRuleCmd{}
	ctx.GetCommand(cmd)
	tree := server.NewParserFromShowConfiguration().Tree
	rule := cmd.Rule
	log.Debug(rule)
	log.Debug(rule.toRules())
	tree.CreateUserFirewallRuleWithNumber(rule.RuleSetName, rule.RuleNumber, rule.toRules())
	tree.Apply(false)
	return nil
}

func changeRuleState(ctx *server.CommandContext) interface{} {
	cmd := &changeRuleStateCmd{}
	ctx.GetCommand(cmd)
	tree := server.NewParserFromShowConfiguration().Tree
	rule := cmd.Rule
	tree.ChangeFirewallRuleState(rule.RuleSetName, rule.RuleNumber, cmd.State)
	tree.Apply(false)
	return nil
}

func getFirewallConfig(ctx *server.CommandContext) interface{} {
	if utils.IsSkipVyosIptables() {
		panic(errors.New("can not use firewall if skipvyosiptables is true"))
	}

	cmd := &getConfigCmd{}
	ctx.GetCommand(cmd)
	ethInfos := make([]ethInfo, 0)

	//sync interfaces
	for _, mac := range cmd.Macs {
		err := utils.Retry(func() error {
			nicname, e := utils.GetNicNameByMac(mac)
			ethInfos = append(ethInfos, ethInfo{
				Name: nicname,
				Mac: mac,
			})
			if e != nil {
				return e
			} else {
				return nil
			}
		}, 5, 1); utils.PanicOnError(err)
	}

	//sync ruleSet and rules
	tree := server.NewParserFromShowConfiguration().Tree
	rs := tree.Get("firewall name")
	rules := make([]ruleInfo, 0)
	ruleSets := make([]ruleSetInfo, 0)
	if ruleSetNodes := rs.Children(); ruleSetNodes == nil {
		return getConfigRsp{Rules:nil, RuleSets:nil, Refs:nil, Interfaces:ethInfos}
	} else {
		for _, ruleSetNode := range ruleSetNodes {
			ruleSet := ruleSetInfo{}
			ruleSet.Name = ruleSetNode.Name()
			ruleSet.ActionType = ruleSetNode.Get("default-action").Value()
			if d := ruleSetNode.Get("enable-default-log"); d != nil {
				ruleSet.EnableDefaultLog = d.Value() == "true"
			}
			ruleSets = append(ruleSets, ruleSet)

			if r := ruleSetNode.Get("rule"); r != nil {
				for _, rc := range r.Children() {
					rules = append(rules, ruleInfo{
						RuleSetName: ruleSetNode.Name(),
						RuleNumber: getRuleNumber(rc),
						Action: rc.GetChildrenValue("action"),
						Protocol: rc.GetChildrenValue("protocol"),
						Tcp:rc.GetChildrenValue("tcp flags"),
						Icmp:rc.GetChildrenValue("icmp type-name"),
						EnableLog: rc.GetChildrenValue("log") == "enable",
						State: getRuleState(rc),
						SourcePort: rc.GetChildrenValue("source port"),
						DestPort:rc.GetChildrenValue("destination port"),
						DestIp:getIp(rc,"destination"),
						SourceIp:getIp(rc,"source"),
						AllowStates:getAllowStates(rc),
						IsDefault:isDefaultRule(rc.Name()),
					})
				}
			}
		}
	}

	//sync ruleSet interface ref
	refs := make([]ethRuleSetRef,0)
	for _,e := range ethInfos {
		if eNode := tree.Getf("interfaces ethernet %s firewall", e.Name); eNode != nil {
			if len(eNode.Children()) == 0 {
				continue
			}
			for _, ec := range eNode.Children() {
				refs = append(refs, ethRuleSetRef{
					Forward:     ec.Name(),
					RuleSetName: ec.GetChildrenValue("name"),
					EthName:     e.Name,
				})
			}
		}
	}
	return getConfigRsp{Rules:rules, RuleSets:ruleSets, Refs:refs, Interfaces:ethInfos}
}

func deleteOldRules(tree *server.VyosConfigTree) {
	//detach ruleSet first
	nics, _ := utils.GetAllNics()
	for _, nic := range nics {
		if iNode := tree.Getf("interfaces ethernet %s firewall out name", nic.Name); iNode != nil {
			iNode.Delete()
		}
	}
	tree.Apply(false)

	rs := tree.Get("firewall name")
	if ruleSetNodes := rs.Children(); ruleSetNodes != nil {
		for _, ruleSetNode := range ruleSetNodes {
			if strings.HasPrefix(ruleSetNode.Name(), USER_RULE_SET_PREFIX) {
				tree.Deletef("firewall name %s", ruleSetNode.Name())
				continue
			}
			if r := ruleSetNode.Get("rule"); r != nil {
				for _, rc := range r.Children() {
					if !isDefaultRule(rc.Name()) {
						tree.Deletef("firewall name %s rule %s", ruleSetNode.Name(), rc.Name())
					}
				}
			}
		}
	}
	tree.Apply(false)
}

func updateRuleSet(ctx *server.CommandContext) interface{} {
	cmd := &updateRuleSetCmd{}
	ctx.GetCommand(cmd)
	tree := server.NewParserFromShowConfiguration().Tree
	tree.SetFirewalRuleSetAction(cmd.Name, cmd.ActionType)
	tree.Apply(false)
	return nil
}

func deleteUserRule(ctx *server.CommandContext) interface{} {
	tree := server.NewParserFromShowConfiguration().Tree
	deleteOldRules(tree)
	return nil
}

func applyUserRules(ctx *server.CommandContext) interface{} {
	cmd := &applyUserRuleCmd{}
	ctx.GetCommand(cmd)
	tree := server.NewParserFromShowConfiguration().Tree
	deleteOldRules(tree)

	for _, ruleSet := range cmd.RuleSets {
		tree.CreateFirewallRuleSet(ruleSet.Name, ruleSet.toRules())
	}

	for _, rule := range cmd.Rules {
		tree.CreateUserFirewallRuleWithNumber(rule.RuleSetName, rule.RuleNumber, rule.toRules())
	}

	for _, ref := range cmd.Refs {
		tree.AttachRuleSetOnInterface(ref.EthName, ref.Forward, ref.RuleSetName)
	}

	for _, action := range cmd.DefaultRuleSetActions {
		tree.SetFirewalRuleSetAction(action.RuleSetName, action.ActionType)
	}

	tree.Apply(false)
	return nil
}

func FirewallEntryPoint() {
	server.RegisterAsyncCommandHandler(fwGetConfigPath, server.VyosLock(getFirewallConfig))
	server.RegisterAsyncCommandHandler(fwDeleteUserRulePath, server.VyosLock(deleteUserRule))
	server.RegisterAsyncCommandHandler(fwCreateRulePath, server.VyosLock(createRule))
	server.RegisterAsyncCommandHandler(fwDeleteRulePath, server.VyosLock(deleteRule))
	server.RegisterAsyncCommandHandler(fwChangeRuleStatePath, server.VyosLock(changeRuleState))
	server.RegisterAsyncCommandHandler(fwCreateRuleSetPath, server.VyosLock(createRuleSet))
	server.RegisterAsyncCommandHandler(fwDeleteRuleSetPath, server.VyosLock(deleteRuleSet))
	server.RegisterAsyncCommandHandler(fwAttachRulesetPath, server.VyosLock(attachRuleSet))
	server.RegisterAsyncCommandHandler(fwDetachRuleSetPath, server.VyosLock(detachRuleSet))
	server.RegisterAsyncCommandHandler(fwApplyUserRulesPath, server.VyosLock(applyUserRules))
	server.RegisterAsyncCommandHandler(fwUpdateRuleSetPath, server.VyosLock(updateRuleSet))
}