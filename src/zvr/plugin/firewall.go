package plugin

import (
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"strconv"
	"strings"
	"zvr/server"
	"zvr/utils"
	"net"
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
	fwApplyRuleSetPath = "/fw/apply/ruleSet/changes"
	zstackRuleNumberFront = 1000
	zstackRuleNumberEnd = 4000
	FIREWALL_RULE_SOURCE_GROUP_SUFFIX = "source"
	FIREWALL_RULE_DEST_GROUP_SUFFIX = "dest"
	IP_SPLIT = ","
)

var moveNicFirewallRetyCount = 0

type ethInfo struct {
	Name string `json:"name"`
	Mac string `json:"mac"`
}

type nicTypeInfo struct {
	Mac string `json:"mac"`
	NicType string `json:"nicType"`
}

type ruleInfo struct {
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
	Mac string `json:"mac"`
	RuleSetInfo ruleSetInfo `json:"ruleSetInfo"`
	Forward string `json:"forward"`
}

type ruleSetInfo struct {
	Name string `json:"name"`
	ActionType string `json:"actionType"`
	EnableDefaultLog bool `json:"enableDefaultLog"`
	Rules []ruleInfo `json:"rules"`
}

type defaultRuleSetAction struct {
	RuleSetName string `json:"ruleSetName"`
	ActionType string `json:"actionType"`
}

type getConfigCmd struct {
	NicTypeInfos []nicTypeInfo `json:"nicInfos"`
}

type getConfigRsp struct {
	Refs []ethRuleSetRef `json:"refs"`
}

type applyUserRuleCmd struct {
	Refs []ethRuleSetRef `json:"refs"`
}

type createRuleCmd struct {
	Ref ethRuleSetRef `json:"ref"`
}

type changeRuleStateCmd struct {
	Rule ruleInfo `json:"rule"`
	State string `json:"state"`
	Mac string `json:"mac"`
	Forward string `json:"forward"`
}

type deleteRuleCmd struct {
	Ref ethRuleSetRef `json:"ref"`
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
	Mac string `json:"mac"`
	Forward string `json:"forward"`
	ActionType string `json:"actionType"`
}

type applyRuleSetChangesCmd struct {
	Refs []ethRuleSetRef `json:"refs"`
	DeleteRules []ruleInfo `json:"deleteRules"`
	NewRules []ruleInfo `json:"newRules"`
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

func (r *ruleInfo) makeGroupName(ruleSetName string, suffix string) string {
	return fmt.Sprintf("%s-%d-%s", ruleSetName, r.RuleNumber, suffix)
}

func (r *ruleInfo) toGroups(suffix string) []string {
	groups := make([]string, 0)
	ipstr := r.SourceIp
	if strings.EqualFold(suffix, FIREWALL_RULE_DEST_GROUP_SUFFIX) {
		ipstr = r.DestIp
	}

	ips := strings.Split(ipstr, IP_SPLIT)
	for _, ip := range(ips)  {
		if _, cidr, err := net.ParseCIDR(ip); err == nil {
			mini := cidr.IP
			max := utils.GetUpperIp(*cidr)
			groups = append(groups, fmt.Sprintf("%s-%s", mini.String(), max.String()))
		} else {
			groups = append(groups, fmt.Sprintf("%s", ip))
		}
	}
	return groups
}

func (r *ruleInfo) toRules(ruleSetName string) []string {
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
		if strings.Contains(r.DestIp, IP_SPLIT) {
			rules = append(rules, fmt.Sprintf("destination group address-group %s", r.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX)))
		} else {
			rules = append(rules, fmt.Sprintf("destination address %s", r.DestIp))
		}
	}
	if r.SourceIp != "" {
		if strings.Contains(r.SourceIp, IP_SPLIT) {
			rules = append(rules, fmt.Sprintf("source group address-group %s", r.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX)))
		} else {
			rules = append(rules, fmt.Sprintf("source address %s",r.SourceIp))
		}
	}
	if r.AllowStates != "" {
		for _,state := range strings.Split(r.AllowStates, IP_SPLIT) {
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
		return t.GetChildrenValue(fmt.Sprintf("%s group address-group",forward))
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

func buildRuleSetName(nicName string, forward string) string {
	return fmt.Sprintf("%s.%s", nicName, forward)
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

		return strings.Join(states, IP_SPLIT)
	}
}

func detachRuleSet(ctx *server.CommandContext) interface{} {
	cmd := &detachRuleSetCmd{}
	ctx.GetCommand(cmd)
	ref := cmd.Ref
	tree := server.NewParserFromShowConfiguration().Tree
	nic, err := utils.GetNicNameByMac(ref.Mac); utils.PanicOnError(err)
	tree.Deletef("interfaces ethernet %s firewall %s", nic, ref.Forward)
	tree.Apply(false)
	return nil
}

func attachRuleSet(ctx *server.CommandContext) interface{} {
	cmd := &attachRuleSetCmd{}
	ctx.GetCommand(cmd)
	ref := cmd.Ref
	tree := server.NewParserFromShowConfiguration().Tree
	nic, err := utils.GetNicNameByMac(ref.Mac); utils.PanicOnError(err)
	ruleSetName := buildRuleSetName(nic, ref.Forward)
	tree.AttachRuleSetOnInterface(nic, ref.Forward, ruleSetName)
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
	ref := cmd.Ref
	tree := server.NewParserFromShowConfiguration().Tree
	nic, err := utils.GetNicNameByMac(ref.Mac); utils.PanicOnError(err)
	ruleSetName := buildRuleSetName(nic, ref.Forward)
	for _, rule := range ref.RuleSetInfo.Rules {
		tree.Deletef("firewall name %s rule %v", ruleSetName, rule.RuleNumber)
		if r := tree.FindGroupByName(rule.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX), "address"); r != nil {
			r.Delete()
		}
		if r := tree.FindGroupByName(rule.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX), "address"); r != nil {
			r.Delete()
		}
	}

	tree.Apply(false)
	return nil
}

func applyRuleSetChanges(ctx *server.CommandContext) interface{} {
	cmd := &applyRuleSetChangesCmd{}
	ctx.GetCommand(cmd)
	tree := server.NewParserFromShowConfiguration().Tree
	refs := cmd.Refs
	for _, ref := range refs {
		nic, err := utils.GetNicNameByMac(ref.Mac); utils.PanicOnError(err)
		ruleSetName := buildRuleSetName(nic, ref.Forward)
		for _, rule := range cmd.DeleteRules {
			tree.Deletef("firewall name %s rule %v", ruleSetName, rule.RuleNumber)
			if r := tree.FindGroupByName(rule.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX), "address"); r != nil {
				r.Delete()
			}
			if r := tree.FindGroupByName(rule.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX), "address"); r != nil {
				r.Delete()
			}
		}

		for _, rule := range cmd.NewRules {
			if rule.SourceIp != "" && strings.ContainsAny(rule.SourceIp, IP_SPLIT) {
				log.Debug(rule.toGroups(FIREWALL_RULE_SOURCE_GROUP_SUFFIX))
				tree.SetGroupsCheckExisting("address", rule.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX), rule.toGroups(FIREWALL_RULE_SOURCE_GROUP_SUFFIX))
			}
			if rule.DestIp != "" && strings.ContainsAny(rule.DestIp, IP_SPLIT) {
				log.Debug(rule.toGroups(FIREWALL_RULE_DEST_GROUP_SUFFIX))
				tree.SetGroupsCheckExisting("address", rule.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX), rule.toGroups(FIREWALL_RULE_DEST_GROUP_SUFFIX))
			}

			tree.CreateUserFirewallRuleWithNumber(ruleSetName, rule.RuleNumber, rule.toRules(ruleSetName))
		}
	}

	tree.Apply(false)
	return nil
}

func createRule(ctx *server.CommandContext) interface{} {
	cmd := &createRuleCmd{}
	ctx.GetCommand(cmd)
	tree := server.NewParserFromShowConfiguration().Tree
	ref := cmd.Ref
	nic, err := utils.GetNicNameByMac(ref.Mac); utils.PanicOnError(err)
	ruleSetName := buildRuleSetName(nic, ref.Forward)
	if rs := tree.Get(fmt.Sprintf("firewall name %s", ruleSetName)); rs == nil {
		tree.CreateFirewallRuleSet(ruleSetName, []string{"default-action accept"})
	}

	for _, rule := range ref.RuleSetInfo.Rules {
		log.Debug(rule)
		log.Debug(rule.toRules(ruleSetName))
		if rule.SourceIp != "" && strings.ContainsAny(rule.SourceIp, IP_SPLIT) {
			log.Debug(rule.toGroups(FIREWALL_RULE_SOURCE_GROUP_SUFFIX))
			tree.SetGroupsCheckExisting("address", rule.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX), rule.toGroups(FIREWALL_RULE_SOURCE_GROUP_SUFFIX))
		}
		if rule.DestIp != "" && strings.ContainsAny(rule.DestIp, IP_SPLIT) {
			log.Debug(rule.toGroups(FIREWALL_RULE_DEST_GROUP_SUFFIX))
			tree.SetGroupsCheckExisting("address", rule.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX), rule.toGroups(FIREWALL_RULE_DEST_GROUP_SUFFIX))
		}

		tree.CreateUserFirewallRuleWithNumber(ruleSetName, rule.RuleNumber, rule.toRules(ruleSetName))
	}

	if rs := tree.Get(fmt.Sprintf("interfaces ethernet %s firewall %s name %s", nic, ref.Forward, ruleSetName)); rs == nil {
		tree.AttachFirewallToInterface(nic, ref.Forward)
	}

	tree.Apply(false)
	return nil
}

func changeRuleState(ctx *server.CommandContext) interface{} {
	cmd := &changeRuleStateCmd{}
	ctx.GetCommand(cmd)
	tree := server.NewParserFromShowConfiguration().Tree
	rule := cmd.Rule
	nic, err := utils.GetNicNameByMac(cmd.Mac); utils.PanicOnError(err)
	ruleSetName := buildRuleSetName(nic, cmd.Forward)
	tree.ChangeFirewallRuleState(ruleSetName, rule.RuleNumber, cmd.State)
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
	tree := server.NewParserFromShowConfiguration().Tree
	//sync interfaces
	for _, nicInfo := range cmd.NicTypeInfos {
		err := utils.Retry(func() error {
			nicname, e := utils.GetNicNameByMac(nicInfo.Mac)
			ethInfos = append(ethInfos, ethInfo{
				Name: nicname,
				Mac: nicInfo.Mac,
			})
			if e != nil {
				return e
			} else {
				return nil
			}
		}, 5, 1); utils.PanicOnError(err)
	}

	//sync ruleSet and rules
	rs := tree.Get("firewall name")
	if ruleSetNodes := rs.Children(); ruleSetNodes == nil {
		return getConfigRsp{Refs:nil}
	} else {
		refs := make([]ethRuleSetRef, 0)
		for _, e := range ethInfos {
			if eNode := tree.Getf("interfaces ethernet %s firewall", e.Name); eNode != nil {
				if len(eNode.Children()) == 0 {
					continue
				}

				for _, ec := range eNode.Children() {
					if ec.GetChildrenValue("name") == "" {
						continue
					}
					mac, err := utils.GetMacByNicName(e.Name)
					utils.PanicOnError(err)

				    ruleSetName := ec.GetChildrenValue("name")
					ruleSetNode := rs.Get(ruleSetName)
					ruleSet := ruleSetInfo{}
					ruleSet.Name = ruleSetNode.Name()
					ruleSet.ActionType = ruleSetNode.Get("default-action").Value()
					if d := ruleSetNode.Get("enable-default-log"); d != nil {
						ruleSet.EnableDefaultLog = d.Value() == "true"
					}

					rules := make([]ruleInfo, 0)

					if r := ruleSetNode.Get("rule"); r != nil {
						for _, rc := range r.Children() {
							rules = append(rules, ruleInfo {
								RuleNumber:  getRuleNumber(rc),
								Action:      rc.GetChildrenValue("action"),
								Protocol:    rc.GetChildrenValue("protocol"),
								Tcp:         rc.GetChildrenValue("tcp flags"),
								Icmp:        rc.GetChildrenValue("icmp type-name"),
								EnableLog:   rc.GetChildrenValue("log") == "enable",
								State:       getRuleState(rc),
								SourcePort:  rc.GetChildrenValue("source port"),
								DestPort:    rc.GetChildrenValue("destination port"),
								DestIp:      getIp(rc, "destination"),
								SourceIp:    getIp(rc, "source"),
								AllowStates: getAllowStates(rc),
								IsDefault:   isDefaultRule(rc.Name()),
							})
						}
					}

					ruleSet.Rules = rules

					refs = append(refs, ethRuleSetRef{
						Forward:     ec.Name(),
						RuleSetInfo: ruleSet,
						Mac:         mac,
					})
				}
			}
		}

		return getConfigRsp{Refs: refs}
	}
}

func deleteOldRules(tree *server.VyosConfigTree) {
	rs := tree.Get("firewall name")
	if ruleSetNodes := rs.Children(); ruleSetNodes != nil {
		for _, ruleSetNode := range ruleSetNodes {
			if r := ruleSetNode.Get("rule"); r != nil {
				for _, rc := range r.Children() {
					if !isDefaultRule(rc.Name()) {
						if g := tree.FindGroupByName(fmt.Sprintf("%s-%s-%s", ruleSetNode.Name(), rc.Name(), FIREWALL_RULE_SOURCE_GROUP_SUFFIX), "address"); g != nil {
							g.Delete()
						}
						if g := tree.FindGroupByName(fmt.Sprintf("%s-%s-%s", ruleSetNode.Name(), rc.Name(), FIREWALL_RULE_DEST_GROUP_SUFFIX), "address"); g != nil {
							g.Delete()
						}
						tree.Deletef("firewall name %s rule %s", ruleSetNode.Name(), rc.Name())
					}
				}
			}
		}
	}
}

func updateRuleSet(ctx *server.CommandContext) interface{} {
	cmd := &updateRuleSetCmd{}
	ctx.GetCommand(cmd)
	tree := server.NewParserFromShowConfiguration().Tree
	nic, err := utils.GetNicNameByMac(cmd.Mac); utils.PanicOnError(err)
	ruleSetName := buildRuleSetName(nic, cmd.Forward)
	tree.SetFirewalRuleSetAction(ruleSetName, cmd.ActionType)
	tree.Apply(false)
	return nil
}

func deleteUserRule(ctx *server.CommandContext) interface{} {
	tree := server.NewParserFromShowConfiguration().Tree
	cmd := &getConfigCmd{}
	ctx.GetCommand(cmd)
	deleteOldRules(tree)
	allowNewStateTrafficOnPubNic(cmd.NicTypeInfos)
	return nil
}

func applyUserRules(ctx *server.CommandContext) interface{} {
	cmd := &applyUserRuleCmd{}
	ctx.GetCommand(cmd)
	tree := server.NewParserFromShowConfiguration().Tree
	deleteOldRules(tree)

	for _, ref := range cmd.Refs {
		nic, err := utils.GetNicNameByMac(ref.Mac); utils.PanicOnError(err)
		ruleSetName := buildRuleSetName(nic, ref.Forward)

		//create ruleSet
		tree.CreateFirewallRuleSet(ruleSetName, ref.RuleSetInfo.toRules())

		//attach ruleset to nic
		tree.AttachRuleSetOnInterface(nic, ref.Forward, ruleSetName)

		//create address group
		for _, rule := range ref.RuleSetInfo.Rules {
			if rule.SourceIp != "" && strings.ContainsAny(rule.SourceIp, IP_SPLIT) {
				log.Debug(rule.toGroups(FIREWALL_RULE_SOURCE_GROUP_SUFFIX))
				tree.SetGroupsCheckExisting("address", rule.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX), rule.toGroups(FIREWALL_RULE_SOURCE_GROUP_SUFFIX))
			}
			if rule.DestIp != "" && strings.ContainsAny(rule.DestIp, IP_SPLIT) {
				log.Debug(rule.toGroups(FIREWALL_RULE_DEST_GROUP_SUFFIX))
				tree.SetGroupsCheckExisting("address", rule.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX), rule.toGroups(FIREWALL_RULE_DEST_GROUP_SUFFIX))
			}
			tree.CreateUserFirewallRuleWithNumber(ruleSetName, rule.RuleNumber, rule.toRules(ruleSetName))
		}
	}
	tree.Apply(false)
	return nil
}

func getIcmpRule(t *server.VyosConfigNode) int {
	for _, cn := range t.Children() {
		number, _ := strconv.Atoi(cn.Name())
		if number > zstackRuleNumberFront {
			continue
		}

		if cn.Get("action accept")!= nil && cn.Get("protocol icmp") != nil {
			return number
		}
	}

	return 0
}

func getStateRule(t *server.VyosConfigNode) (int, string) {
	nicType := ""
	for _, cn := range t.Children() {
		number, _ := strconv.Atoi(cn.Name())
		if number > zstackRuleNumberFront && number < zstackRuleNumberEnd {
			continue
		}

		if cn.Get("action accept") != nil && cn.Get("state established enable") != nil && cn.Get("state related enable") != nil {
			if cn.Get("description") != nil || cn.Get("source") != nil {
				continue
			}

			if cn.Get("state invalid enable") != nil && cn.Get("state new enable") != nil {
				nicType = "Private"
				return number, nicType
			}

			return number, nicType
		}
	}

	return 0, nicType
}

func moveLowPriorityRulesToTheBack () {
	err := utils.Retry(func() error {
		moveNicInForwardFirewall()
		if moveNicFirewallRetyCount != 0 {
			return fmt.Errorf("failed to move nic firewall")
		} else {
			return nil
		}
	}, 3, 1);utils.LogError(err)
}

func moveNicInForwardFirewall() {
	defer func() {
		if err := recover(); err != nil {
			log.Info("move nic firewall config failed, retry it...")
			moveNicFirewallRetyCount ++
		} else {
			moveNicFirewallRetyCount = 0
		}
	}()
	//move zvrboot nic firewall config to 4000 behind
	tree := server.NewParserFromShowConfiguration().Tree
	nics, _ := utils.GetAllNics()
	deleteCommands := []string{}
	for _, nic := range nics {
		eNode := tree.Getf("firewall name %s.in rule", nic.Name)
		if eNode == nil {
			continue
		}

		ruleNumber, nicType := getStateRule(eNode)
		if ruleNumber != 0 && ruleNumber < zstackRuleNumberFront {
			deleteCommands = append(deleteCommands, fmt.Sprintf("firewall name %s.in rule %v", nic.Name, ruleNumber))
			if nicType == "Private" {
				tree.SetZStackFirewallRuleOnInterface(nic.Name, "behind", "in",
					"action accept",
					"state established enable",
					"state related enable",
					"state invalid enable",
					"state new enable",
				)
			} else {
				tree.SetZStackFirewallRuleOnInterface(nic.Name, "behind", "in",
					"action accept",
					"state established enable",
					"state related enable",
				)
			}
		}

		if ruleNumber := getIcmpRule(eNode); ruleNumber != 0 {
			deleteCommands = append(deleteCommands, fmt.Sprintf("firewall name %s.in rule %v", nic.Name, ruleNumber))
			tree.SetZStackFirewallRuleOnInterface(nic.Name, "behind", "in",
				"action accept",
				"protocol icmp",
			)
		}

		if nicType != "Private" {
			if eNode.Get("9999") == nil {
				tree.SetFirewallWithRuleNumber(nic.Name, "in", ROUTE_STATE_NEW_ENABLE_FIREWALL_RULE_NUMBER,
					"action accept",
					"state new enable",
				)
			}
		} else {
			if eNode.Get("9999") != nil {
				tree.Deletef("firewall name %v.in rule %v", nic.Name, 9999)
			}
		}
	}

	if len(deleteCommands) != 0 {
		for _, command := range deleteCommands {
			tree.Delete(command)
		}
	}

	tree.Apply(false)
}

func allowNewStateTrafficOnPubNic(nicInfos []nicTypeInfo) {
	tree := server.NewParserFromShowConfiguration().Tree
	for _, nicInfo := range nicInfos {
		if nicInfo.NicType == "Private" {
			continue
		}
		nicName, err := utils.GetNicNameByMac(nicInfo.Mac); utils.PanicOnError(err)
		eNode := tree.Getf("firewall name %s.in rule", nicName)
		if eNode == nil {
			continue
		}
		if eNode.Get("9999") == nil {
			tree.SetFirewallWithRuleNumber(nicName, "in", ROUTE_STATE_NEW_ENABLE_FIREWALL_RULE_NUMBER,
				"action accept",
				"state new enable",
			)
		} else {
			if eNode.Get("9999 disable") != nil {
				tree.Deletef("firewall name %v.in rule %v disable", nicName, 9999)
			}
		}
	}
	tree.Apply(false)
}

func FirewallEntryPoint() {
	server.RegisterAsyncCommandHandler(fwApplyRuleSetPath, server.VyosLock(applyRuleSetChanges))
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
	moveLowPriorityRulesToTheBack()
}