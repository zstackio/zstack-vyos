package utils

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	IPTABLES_RULENUMBER_9999 = 9999
	IPTABLES_RULENUMBER_MAX  = 10000
)

const (
	SystemTopRule      = "default rule"
	SystemLastLastRule = "default rule 9999"
	SystemLastRule     = "default rule 10000"

	/*network service rule comment*/
	FirewallRule           = "firewall rule"
	PortFordingRuleComment = "pf rule"
	EipRuleComment         = "eip rule"
	IpsecRuleComment       = "IPSec rule"
	LbRuleComment          = "lb rule"
	SNATComment            = "snat rule"
	PolicyRouteComment     = "policy route rule"

	PolicyRouteChainPrefix     = "zs-rt-"
	PolicyRouteRuleChainPrefix = "zs-rule-"
)

const (
	VYOS_INPUT_ROOT_CHAIN  = "VYATTA_FW_LOCAL_HOOK"
	VYATTA_PRE_FW_IN_HOOK  = "VYATTA_PRE_FW_IN_HOOK"
	VYATTA_POST_FW_IN_HOOK = "VYATTA_POST_FW_IN_HOOK"

	VYOS_PRE_FW_FWD_HOOK    = "VYATTA_PRE_FW_FWD_HOOK"
	VYOS_FWD_ROOT_CHAIN     = "VYATTA_FW_IN_HOOK"
	VYOS_FWD_OUT_ROOT_CHAIN = "VYATTA_FW_OUT_HOOK"
	VYOS_POST_FW_FWD_HOOK   = "VYATTA_POST_FW_FWD_HOOK"

	LOCAL_CHAIN_SYSTEM_RULE_RULE_NUMBER_MIN = 1
	LOCAL_CHAIN_SYSTEM_RULE_RULE_NUMBER_MAX = 1000
	LOCAL_CHAIN_SERVICE_RULE_NUMBER_MIN     = 4000
	LOCAL_CHAIN_SERVICE_RULE_NUMBER_MAX     = 9000

	FORWARD_CHAIN_SYSTEM_RULE_RULE_NUMBER_MIN = 4000
	FORWARD_CHAIN_SYSTEM_RULE_RULE_NUMBER_MAX = 5000
	FORWARD_CHAIN_SERVICE_RULE_NUMBER_MIN     = 5001
	FORWARD_CHAIN_SERVICE_RULE_NUMBER_MAX     = 9000
)

const (
	ACTION  = "action"
	COMMNET = "comment"
)

var filterLocalRulesPriority = map[string]int{
	SystemTopRule:          LOCAL_CHAIN_SYSTEM_RULE_RULE_NUMBER_MIN,
	IpsecRuleComment:       5000,
	PortFordingRuleComment: 6000,
	LbRuleComment:          7000,
	EipRuleComment:         8000,
	SystemLastLastRule:     IPTABLES_RULENUMBER_9999,
	SystemLastRule:         IPTABLES_RULENUMBER_MAX,
}

var filterForwardRulesPriority = map[string]int{
	SystemTopRule:          FORWARD_CHAIN_SYSTEM_RULE_RULE_NUMBER_MIN,
	FirewallRule:           1000,
	IpsecRuleComment:       5000,
	PortFordingRuleComment: 6000,
	EipRuleComment:         7001,
	SystemLastLastRule:     IPTABLES_RULENUMBER_9999,
	SystemLastRule:         IPTABLES_RULENUMBER_MAX,
}

var filterOutRulesPriority = map[string]int{
	FirewallRule:       1000,
	SystemLastLastRule: IPTABLES_RULENUMBER_9999,
	SystemLastRule:     IPTABLES_RULENUMBER_MAX,
}

var snatRulesPriority = map[string]int{
	SystemTopRule:    1,
	IpsecRuleComment: 1000,
	EipRuleComment:   2000,
	SNATComment:      IPTABLES_RULENUMBER_MAX,
}

var dnatRulesPriority = map[string]int{
	PortFordingRuleComment: 1000,
	EipRuleComment:         900,
	PolicyRouteComment:     800, /* policy route is in mangle table, put code here for a moment */
}

var filterFORWARDRulesPriority = map[string]int{
	VYOS_PRE_FW_FWD_HOOK:    0,
	VYOS_FWD_ROOT_CHAIN:     1,
	VYOS_FWD_OUT_ROOT_CHAIN: 2,
	VYOS_POST_FW_FWD_HOOK:   3,
}

var INPUTRulesPriority = map[string]int{
	VYATTA_PRE_FW_IN_HOOK:  0,
	VYOS_INPUT_ROOT_CHAIN:  1,
	VYATTA_POST_FW_IN_HOOK: 2,
}

type RuleSetDirection int

const (
	RULESET_IN RuleSetDirection = iota
	RULESET_LOCAL
	RULESET_OUT
	RULESET_DNAT
	RULESET_SNAT
	INPUT
	FORWARD
	PREROUTING
	POSTROUTING
	CHAIN_ERROR
)

func (d RuleSetDirection) String() string {
	switch d {
	case RULESET_IN:
		return ".in"
	case RULESET_LOCAL:
		return ".local"
	case RULESET_OUT:
		return ".out"
	case RULESET_DNAT:
		return "PREROUTING"
	case RULESET_SNAT:
		return "POSTROUTING"
	case FORWARD:
		return "FORWARD"
	case PREROUTING:
		return "PREROUTING"
	case POSTROUTING:
		return "POSTROUTING"
	case INPUT:
		return "INPUT"
	default:
		return ".unkonwn"
	}
}

func GetRuleSetName(nic string, ch RuleSetDirection) string {
	return nic + ch.String()
}

func (d RuleSetDirection) getPriorityByAction(action string) (int, bool) {
	var m *map[string]int
	switch d {
	case INPUT:
		m = &INPUTRulesPriority
	case FORWARD:
		m = &filterFORWARDRulesPriority
	default:
		return 0, false
	}

	p, ok := (*m)[action]
	return p, ok
}

func (d RuleSetDirection) getPriorityByComment(comment string) (int, bool) {
	var m *map[string]int
	switch d {
	case RULESET_IN:
		m = &filterForwardRulesPriority
	case RULESET_LOCAL:
		m = &filterLocalRulesPriority
	case RULESET_OUT:
		m = &filterOutRulesPriority
	case RULESET_DNAT:
		m = &dnatRulesPriority
	case RULESET_SNAT:
		m = &snatRulesPriority
	default:
		return 0, false
	}

	p, ok := (*m)[comment]
	return p, ok
}

type VyosIpTableHelper struct{}

func (p VyosIpTableHelper) parseIpTableRule(rule *IpTableRule, t *IpTables) *IpTableRule {
	priority, err := getPriority(rule)
	if priority == 0 || err != nil {
		rule.priority = t.priorityOfLastRule
		return rule
	}

	rule.priority = priority
	/* firewall rule priority is same to rulenum */
	if strings.Contains(rule.GetComment(), FirewallRule) {
		rule.ruleNumber = priority
		return rule
	} else {
		_, _, ruleNum, err := parseRuleNumberFromComment(rule.GetComment())
		if ruleNum != 0 && err == nil {
			rule.ruleNumber = ruleNum
		}

		return rule
	}
}

func (p VyosIpTableHelper) getNextRuleNumber(t *IpTables, rule *IpTableRule) int {
	/* firewall rule already has rule No.  */
	if rule.ruleNumber != 0 {
		return rule.ruleNumber
	}

	/* no comment, priority is 0 */
	if rule.comment == "" {
		return 0
	}

	/* TODO: only rule in filter table need rule No. */
	if t.Name != FirewallTable {
		return 0
	}

	existed := map[int]int{}
	for _, r := range t.Rules {
		if r.chainName == rule.chainName {
			if r.ruleNumber != 0 {
				existed[r.ruleNumber] = r.ruleNumber
			}
		}
	}

	ruleNo := 0
	if strings.Contains(rule.chainName, RULESET_LOCAL.String()) {
		if strings.Contains(rule.comment, SystemTopRule) {
			for i := LOCAL_CHAIN_SYSTEM_RULE_RULE_NUMBER_MIN; i <= LOCAL_CHAIN_SYSTEM_RULE_RULE_NUMBER_MAX; i++ {
				if _, ok := existed[i]; !ok {
					ruleNo = i
					break
				}
			}
		} else {
			for i := LOCAL_CHAIN_SERVICE_RULE_NUMBER_MIN; i <= LOCAL_CHAIN_SERVICE_RULE_NUMBER_MAX; i++ {
				if _, ok := existed[i]; !ok {
					ruleNo = i
					break
				}
			}
		}
	} else if strings.Contains(rule.chainName, RULESET_IN.String()) {
		if strings.Contains(rule.comment, SystemTopRule) {
			for i := FORWARD_CHAIN_SYSTEM_RULE_RULE_NUMBER_MIN; i <= FORWARD_CHAIN_SYSTEM_RULE_RULE_NUMBER_MAX; i++ {
				if _, ok := existed[i]; !ok {
					ruleNo = i
					break
				}
			}
		} else {
			for i := FORWARD_CHAIN_SERVICE_RULE_NUMBER_MIN; i <= FORWARD_CHAIN_SERVICE_RULE_NUMBER_MAX; i++ {
				if _, ok := existed[i]; !ok {
					ruleNo = i
					break
				}
			}
		}
	}

	return ruleNo
}

func getComment(rule *IpTableRule) string {
	items := strings.Split(rule.GetComment(), "@")
	if rule.ruleNumber != 0 {
		return fmt.Sprintf("%s@%s-%d", items[0], rule.chainName, rule.ruleNumber)
	} else {
		return fmt.Sprintf("%s@%s", items[0], rule.chainName)
	}
}

func getPriority(rule *IpTableRule) (int, error) {
	c := CHAIN_ERROR
	/* if chain is default chain */
	if rule.chainName == FORWARD.String() {
		c = FORWARD
	} else if rule.chainName == INPUT.String() {
		c = INPUT
	}

	if c != CHAIN_ERROR {
		p, ok := c.getPriorityByAction(rule.action)
		if ok {
			return p, nil
		}
	}

	return getPriorityFromComment(rule)
}

func getPriorityFromComment(rule *IpTableRule) (int, error) {
	/* if rule is added by customer, no comment or comment format error,
	   it priority is same to last priority */
	if rule.comment == "" {
		rule.priority = 0
		return 0, fmt.Errorf("no comment for priotity [%s]", rule.comment)
	}

	comment, _, ruleNum, err := parseRuleNumberFromComment(rule.GetComment())
	if err == nil && strings.Contains(rule.GetComment(), FirewallRule) {
		return ruleNum, nil
	}

	c := PREROUTING
	if strings.Contains(rule.GetChainName(), RULESET_LOCAL.String()) {
		c = RULESET_LOCAL
	} else if strings.Contains(rule.GetChainName(), RULESET_IN.String()) {
		c = RULESET_IN
	} else if strings.Contains(rule.GetChainName(), RULESET_OUT.String()) {
		c = RULESET_OUT
	} else if strings.Contains(rule.GetChainName(), RULESET_SNAT.String()) {
		c = RULESET_SNAT
	} else if strings.Contains(rule.GetChainName(), RULESET_DNAT.String()) {
		c = RULESET_DNAT
	} else {
		return 0, fmt.Errorf("no define priority for chainname [%s]", rule.GetChainName())
	}

	p, ok := c.getPriorityByComment(comment)
	if !ok {
		return 0, fmt.Errorf("no define priority for comment [%s]", comment)
	} else {
		return p, nil
	}
}

/* this api is called before add rule to iptables */
func (r *IpTableRule) SetComment(comment string) *IpTableRule {
	r.setComment(comment)
	r.priority, _ = getPriorityFromComment(r)
	r.comment = getComment(r)

	return r
}

/* this api is called before add rule to iptables */
func (r *IpTableRule) SetCompareTarget(compare bool) *IpTableRule {
	r.compareTarget = compare

	return r
}

func NewDefaultIpTableRule(ruleSetName string, ruleNumber int) *IpTableRule {
	var rule IpTableRule
	rule.chainName = ruleSetName
	c := SystemLastRule
	if ruleNumber == IPTABLES_RULENUMBER_9999 {
		c = SystemLastLastRule
		rule.SetState([]string{IPTABLES_STATE_NEW})
	}

	rule.comment = c
	rule.comment = getComment(&rule)
	if strings.Contains(ruleSetName, RULESET_OUT.String()) {
		rule.priority = filterOutRulesPriority[c]
	} else {
		rule.priority = filterForwardRulesPriority[c]
	}
	rule.ruleNumber = ruleNumber

	return &rule
}

/*
firewall comment format: "system rule@eth1.in-1001"

	return comment, chain name, rule number when success
*/
func parseRuleNumberFromComment(comment string) (string, string, int, error) {
	fields := strings.Split(comment, "@")
	if len(fields) < 2 {
		return fields[0], "", 0, fmt.Errorf("comment format error: %s", comment)
	}

	items := strings.Split(fields[1], "-")
	if len(items) < 2 {
		return fields[0], items[0], 0, nil
	}

	v, err := strconv.Atoi(items[1])
	return fields[0], items[0], v, err
}

func SetFirewallRuleNumber(r *IpTableRule, ruleSetName string, ruleNumber int) *IpTableRule {
	r.comment = FirewallRule
	r.priority = ruleNumber
	r.ruleNumber = ruleNumber
	r.comment = getComment(r)
	return r
}

func IsDefaultRule(r *IpTableRule) bool {
	return strings.Contains(r.comment, SystemLastRule) && r.action != IPTABLES_ACTION_LOG
}

func GetFirewallIpTableRule(t *IpTables) []*IpTableRule {
	var rules []*IpTableRule
	for _, r := range t.Rules {
		if strings.Contains(r.comment, FirewallRule) {
			rules = append(rules, r.Copy())
		}
	}

	return rules
}

func GetPimdIpTableRule(t *IpTables) []*IpTableRule {
	var rules []*IpTableRule
	for _, r := range t.Rules {
		if !strings.Contains(r.chainName, RULESET_LOCAL.String()) {
			continue
		}

		if r.proto == IPTABLES_PROTO_PIMD || r.proto == IPTABLES_PROTO_IGMP {
			rules = append(rules, r.Copy())
		}
	}

	return rules
}

func GetOSPFIpTableRule(t *IpTables) []*IpTableRule {
	var rules []*IpTableRule
	for _, r := range t.Rules {
		if r.proto == IPTABLES_PROTO_OSPF {
			rules = append(rules, r.Copy())
		}
	}

	return rules
}

func GetDnsIpTableRule(t *IpTables) []*IpTableRule {
	var rules []*IpTableRule
	for _, r := range t.Rules {
		if !strings.Contains(r.chainName, RULESET_LOCAL.String()) {
			continue
		}

		if r.dstPort == "53" {
			rules = append(rules, r.Copy())
		}
	}

	return rules
}

func GetFirewallInputChains(t *IpTables) []string {
	var chains []string
	for _, c := range t.Chains {
		if strings.Contains(c.Name, RULESET_IN.String()) {
			chains = append(chains, c.Name)
		}
	}

	return chains
}

func GetFirewallOutputChains(t *IpTables) []string {
	var chains []string
	for _, c := range t.Chains {
		if strings.Contains(c.Name, RULESET_OUT.String()) {
			chains = append(chains, c.Name)
		}
	}

	return chains
}

func SetNicDefaultFirewallRule(nic string, defaultAction string) error {
	t := NewIpTables(FirewallTable)

	var rules []*IpTableRule
	nicLocalChain := GetRuleSetName(nic, RULESET_LOCAL)

	rule := NewDefaultIpTableRule(nicLocalChain, IPTABLES_RULENUMBER_MAX)
	if strings.ToUpper(defaultAction) == IPTABLES_ACTION_REJECT {
		rule.SetAction(IPTABLES_ACTION_REJECT)
	} else {
		rule.SetAction(IPTABLES_ACTION_RETURN)
	}
	rules = append(rules, rule)

	nicFwdChain := GetRuleSetName(nic, RULESET_IN)

	rule = NewDefaultIpTableRule(nicFwdChain, IPTABLES_RULENUMBER_MAX)
	if strings.ToUpper(defaultAction) == IPTABLES_ACTION_REJECT {
		rule.action = IPTABLES_ACTION_REJECT
	} else {
		rule.action = IPTABLES_ACTION_RETURN
	}
	rules = append(rules, rule)

	t.AddIpTableRules(rules)

	return t.Apply()
}

func DestroyNicFirewall(nic string) error {
	t := NewIpTables(FirewallTable)

	t.removeChainRules(GetRuleSetName(nic, RULESET_LOCAL))
	t.removeChainRules(GetRuleSetName(nic, RULESET_IN))
	t.removeChainRules(GetRuleSetName(nic, RULESET_OUT))

	return t.Apply()
}

func InitNicFirewall(nic string, ip string, pubNic bool, defaultAction string) error {
	InitVyattaFilterTable()

	table := NewIpTables(FirewallTable)
	localChain := GetRuleSetName(nic, RULESET_LOCAL)
	forwardChain := GetRuleSetName(nic, RULESET_IN)
	outChain := GetRuleSetName(nic, RULESET_OUT)
	table.AddChain(localChain)
	table.AddChain(forwardChain)
	table.AddChain(outChain)

	var rules []*IpTableRule
	rule := NewIpTableRule(VYOS_INPUT_ROOT_CHAIN)
	rule.SetAction(localChain).SetInNic(nic)
	rules = append(rules, rule)

	rule = NewIpTableRule(VYOS_FWD_ROOT_CHAIN)
	rule.SetAction(forwardChain).SetInNic(nic)
	rules = append(rules, rule)

	rule = NewIpTableRule(VYOS_FWD_OUT_ROOT_CHAIN)
	rule.SetAction(outChain).SetOutNic(nic)
	rules = append(rules, rule)

	/* add Rules for FORWARD chain */
	rule = NewIpTableRule(forwardChain)
	rule.SetAction(IPTABLES_ACTION_RETURN)
	rule.SetComment(SystemTopRule)
	rule.SetState([]string{IPTABLES_STATE_RELATED, IPTABLES_STATE_ESTABLISHED})
	rules = append(rules, rule)

	rule = NewDefaultIpTableRule(forwardChain, IPTABLES_RULENUMBER_9999)
	rule.SetAction(IPTABLES_ACTION_RETURN)
	rules = append(rules, rule)

	rule = NewDefaultIpTableRule(forwardChain, IPTABLES_RULENUMBER_MAX)
	rule.SetAction(defaultAction)
	rules = append(rules, rule)

	sshPort := GetSshPortFromBootInfo()
	if IsIpv4Address(ip) {
		rule = NewIpTableRule(localChain)
		rule.SetAction(IPTABLES_ACTION_RETURN).SetComment(SystemTopRule)
		rule.SetDstIp(ip + "/32").SetState([]string{IPTABLES_STATE_RELATED, IPTABLES_STATE_ESTABLISHED})
		rules = append(rules, rule)

		rule = NewIpTableRule(localChain)
		rule.SetAction(IPTABLES_ACTION_RETURN).SetComment(SystemTopRule)
		rule.SetDstIp(ip + "/32").SetProto(IPTABLES_PROTO_ICMP)
		rules = append(rules, rule)

		if IsMgtNic(nic) {
			rule = NewIpTableRule(localChain)
			rule.SetAction(IPTABLES_ACTION_RETURN).SetComment(SystemTopRule)
			rule.SetDstIp(ip + "/32").SetProto(IPTABLES_PROTO_TCP).SetDstPort(strconv.FormatFloat(sshPort, 'f', 0, 64))
			rules = append(rules, rule)

			rule = NewIpTableRule(localChain)
			rule.SetAction(IPTABLES_ACTION_RETURN).SetComment(SystemTopRule)
			rule.SetDstIp(ip + "/32").SetProto(IPTABLES_PROTO_TCP).SetDstPort("7272")
			rules = append(rules, rule)
		} else {
			rule = NewIpTableRule(localChain)
			rule.SetAction(IPTABLES_ACTION_REJECT).SetRejectType(REJECT_TYPE_ICMP_UNREACHABLE)
			rule.SetComment(SystemTopRule).SetDstIp(ip + "/32").SetProto(IPTABLES_PROTO_TCP).SetDstPort(strconv.FormatFloat(sshPort, 'f', 0, 64))
			rules = append(rules, rule)
		}
	}

	rule = NewDefaultIpTableRule(localChain, IPTABLES_RULENUMBER_MAX)
	rule.SetAction(defaultAction)
	rules = append(rules, rule)

	table.AddIpTableRules(rules)

	return table.Apply()
}

func InitNatRule() {
	if !IsSkipVyosIptables() {
		return
	}

	/*flush raw table to clear NOTRACK rule at startup*/
	cmd := Bash{
		Command: "sudo iptables -t raw -C DNAT -j NOTRACK && sudo iptables -t raw -D DNAT -j NOTRACK;" +
			"sudo iptables -t raw -C PREROUTING -j NOTRACK && sudo iptables -t raw -D PREROUTING -j NOTRACK;" +
			"sudo iptables -t raw -C OUTPUT -j NOTRACK && sudo iptables -t raw -D OUTPUT -j NOTRACK;" +
			"sudo iptables -t raw -A DNAT -p vrrp -j NOTRACK;" + // do not track VRRP
			"sudo iptables -t raw -A OUTPUT -p vrrp -j NOTRACK",
	}
	cmd.Run()

	return
}

func InitVyattaFilterTable() {
	if !IsSkipVyosIptables() {
		return
	}

	/* INPT chain rule
	rule sequence:

	-A INPUT -j VYATTA_PRE_FW_IN_HOOK
	-A INPUT -j VYATTA_FW_LOCAL_HOOK
	-A INPUT -j VYATTA_POST_FW_IN_HOOK
	*/

	table := NewIpTables(FirewallTable)
	table.AddChain(VYOS_INPUT_ROOT_CHAIN)
	table.AddChain(VYOS_FWD_ROOT_CHAIN)
	table.AddChain(VYOS_FWD_OUT_ROOT_CHAIN)

	rule := NewIpTableRule("INPUT")
	rule.SetAction(VYOS_INPUT_ROOT_CHAIN).SetCompareTarget(true).SetPriority(1)
	table.addIpTableRule(rule)

	/*add FORWARD chain rule
		rule sequence:

		-A FORWARD -j VYATTA_PRE_FW_FWD_HOOK
	        -A FORWARD -j VYATTA_FW_IN_HOOK
	        -A FORWARD -j VYATTA_FW_OUT_HOOK
	        -A FORWARD -j VYATTA_POST_FW_FWD_HOOK
	*/
	rule = NewIpTableRule("FORWARD")
	rule.SetAction(VYOS_FWD_ROOT_CHAIN).SetCompareTarget(true).SetPriority(1)
	table.addIpTableRule(rule)

	rule = NewIpTableRule("FORWARD")
	rule.SetAction(VYOS_FWD_OUT_ROOT_CHAIN).SetCompareTarget(true).SetPriority(2)
	table.addIpTableRule(rule)

	table.Apply()

	return
}
