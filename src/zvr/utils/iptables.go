package utils

import (
	"fmt"
	"strings"
	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
	"sort"
)

type Chain int
const (
	IN Chain = iota
	LOCAL
	PREROUTING
	POSTROUTING
)

func (this Chain) string() string {
	switch this {
	case IN:
		return ".zs.in"
	case LOCAL:
		return ".zs.local"
	case PREROUTING:
		return "zs.dnat"
	case POSTROUTING:
		return "zs.snat"
	default:
		return ".unkonwn"
	}
}
func getChainName(nic string, ch Chain) string {
	return nic + ch.string()
}

const (
	TCP = "tcp"
	UDP = "udp"
	ICMP = "icmp"
	ESP = "esp"
	AH = "ah"
)

const (
	ACCEPT = "ACCEPT"
	RETURN = "RETURN"
	REJECT = "REJECT"
	DNAT = "DNAT"
	SNAT = "SNAT"
	DROP = "DROP"
)

const (
	NEW = "NEW"
	RELATED = "RELATED"
	ESTABLISHED = "ESTABLISHED"
	INVALID = "INVALID"
)

const (
	SYN = "SYN"
)

const (
	FirewallTable = "filter"
	NatTable = "nat"
	DefaultTopRuleComment = "Default-rules-top" /* must be at top of firewall */
	DefaultBottomRuleComment = "Default-rules-bottom" /* must be at bottom of firewall */
	PortFordingRuleComment = "PF-rules-for-"
	DnsRuleComment = "DNS-rules"
	DHCPRuleComment = "DHCP-rules"
	EipRuleComment = "EIP-rules-for-"
	IpsecRuleComment = "IPSEC-rules-for-"         /* must be at top of postrouting of nat */
	LbRuleComment = "LB-rules-for-"
	SNATComment = "SNAT-rules-for-"
	ManagementComment = "Management-rules"
	OSPFComment = "OSPF-rules"
)

var rulesPriority = map[string]int{
"Default-rules-top": 	1000,
"Management-rules": 	900,
"DNS-rules":        	800,
"DHCP-rules":        	700,
	"OSPF-rules":   650,
"IPSEC-rules-": 	600,
"PF-rules-":    	500,
"LB-rules-":            400,
"EIP-rules-":           300,
"SNAT-rules-":          200,
"Default-rules-bottom": 100,
}

const (
	Predefined_local_chain = "VYATTA_PRE_FW_IN_HOOK"
	Predefined_forward_chain = "VYATTA_PRE_FW_FWD_HOOK"
)

/* iptables of same kind are group together, the order is
   Default-rules-top > management-rules > Dns-rules > DHCP-rules > Ipsec-rules-for > Pf-rules-for >
   LB-rules-for > Eip-rules-for > SNAT-rules-for-> Default-rules-bottom*/
func commentCompare(comment1, comment2 string) int {
	c1 := strings.Split(comment1, "for")
	c2 := strings.Split(comment2, "for")
	return rulesPriority[c1[0]] - rulesPriority[c2[0]];
}

type IptablesRule struct {
	chainName         string
	proto             string
	src, dest         string
	srcPort, destPort int
	states            []string
	action            string
	comment           string
	inNic, outNic     string
	tcpflags          []string
}

func NewIptablesRule(proto string, src, dest string, srcPort, destPort int,
           states []string, action string,  comment string) IptablesRule {
	return IptablesRule{proto: proto, src: src, dest: dest, srcPort: srcPort,
		destPort:destPort, states: states, action:action, comment:comment,
		outNic: "", inNic: "", tcpflags:nil}
}

func NewEipIptablesRule(src, dest string, action string,  comment string, outNic string) IptablesRule {
	return IptablesRule{proto: "", src: src, dest: dest, srcPort: 0,
		destPort:0, states: nil, action:action, comment:comment,
		outNic: outNic, inNic: "", tcpflags:nil}
}

func NewIpsecsIptablesRule(proto string, src, dest string, srcPort, destPort int,
states []string, action string,  comment string, inNic, outNic string) IptablesRule {
	return IptablesRule{proto: proto, src: src, dest: dest, srcPort: srcPort,
		destPort:destPort, states: states, action:action, comment:comment,
		outNic: outNic, inNic: inNic, tcpflags: nil}
}

func NewLoadBalancerIptablesRule(proto string, dest string, destPort int, action string,
        comment string, tcpflags []string) IptablesRule {
	return IptablesRule{proto: proto, src: "", dest: dest, srcPort: 0,
		destPort:destPort, states: nil, action:action, comment:comment,
		outNic: "", inNic: "", tcpflags:tcpflags}
}

func NewSnatIptablesRule(src, dest, outNic, action, comment string) IptablesRule {
	return IptablesRule{proto: "", src: src, dest: dest, srcPort: 0,
		destPort:0, states: nil, action:action, comment:comment,
		outNic: outNic, inNic: "", tcpflags:nil}
}

func (iptableRule IptablesRule)string() []string  {
	rules := []string{}
	if iptableRule.src != "" && iptableRule.action != DNAT {
		rules = append(rules, "-s " + iptableRule.src)
	}

	if iptableRule.dest != "" && iptableRule.action != SNAT {
		rules = append(rules, "-d " + iptableRule.dest)
	}

	if iptableRule.outNic != "" {
		rules = append(rules, "-o " + iptableRule.outNic)
	}

	if iptableRule.proto != "" {
		rules = append(rules, "-p " + iptableRule.proto)
		if iptableRule.srcPort != 0 && iptableRule.action != DNAT {
			rules = append(rules, "-m " + iptableRule.proto)
			rules = append(rules, fmt.Sprintf("--sport %d ", iptableRule.srcPort))
		}

		if iptableRule.destPort != 0 {
			rules = append(rules, "-m " + iptableRule.proto)
			rules = append(rules, fmt.Sprintf("--dport %d ", iptableRule.destPort))
		}
	}

	rules = append(rules, "-m comment --comment " + iptableRule.comment)

	if iptableRule.states != nil {
		rules = append(rules, "-m state --state " + strings.Join(iptableRule.states, ","))
	}

	switch iptableRule.action {
	case REJECT:
		rules = append(rules, "-j REJECT --reject-with icmp-port-unreachable")
	case DNAT:
		if iptableRule.srcPort != 0 {
			rules = append(rules, fmt.Sprintf("-j DNAT --to-destination %s:%d", iptableRule.src, iptableRule.srcPort))
		} else {
			rules = append(rules, fmt.Sprintf("-j DNAT --to-destination %s", iptableRule.src))
		}
	case SNAT:
		rules = append(rules, fmt.Sprintf("-j SNAT --to-source %s", iptableRule.dest))
	default:
		rules = append(rules, "-j " + iptableRule.action)
	}

	return rules
}

func SetDefaultRule(nic string, defaultAction string) error {
	/* old default action maybe different, it can not be deleted in InsertFireWallRule,
	 * so delete it before */
	DeleteFirewallRuleByComment(nic, DefaultBottomRuleComment)

	rule := getDefaultIptablesRule()
	if defaultAction == "reject" {
		rule.action = REJECT
	} else {
		rule.action = ACCEPT
	}
	rule.comment = DefaultBottomRuleComment
	if err := InsertFireWallRule(nic, rule, LOCAL); err != nil {
		return err
	}

	rule = getDefaultIptablesRule()
	rule.states = []string {NEW}
	rule.action = RETURN
	rule.comment = DefaultBottomRuleComment
	if err := InsertFireWallRule(nic, rule, IN); err != nil{
		return err
	}

	rule = getDefaultIptablesRule()
	if defaultAction == "reject" {
		rule.action = REJECT
	} else {
		rule.action = ACCEPT
	}
	rule.comment = DefaultBottomRuleComment
	if err := InsertFireWallRule(nic, rule, IN); err != nil {
		return err
	}

	return nil
}

func getCommentsFromRule(rule string) string {
	elements := strings.Split(rule, " ")
	prev := ""
	comment := ""
	for _, e := range elements {
		if prev == "--comment" {
			comment = e
			break
		}
		prev = e
	}

	return strings.Trim(comment, "\"")
}

func InsertFireWallRule(nic string, rule IptablesRule, ch Chain)  error {
	rules := strings.Join(rule.string(), " ")
	chainName := getChainName(nic, ch)
	if exist, _ := isExist(FirewallTable, chainName, rules); exist {
		log.Debugf("iptables %s %s already existed", FirewallTable, rules)
		return nil
	}

	olds, err := listRule(FirewallTable, chainName)
	if err != nil {
		PanicOnError(fmt.Errorf("list iptables in %s faild %s", chainName, err.Error()))
		return err
	}

	num := 1
	for _, r := range olds {
		/* insert by comment order */
		comment := getCommentsFromRule(r)
		/* skip rules:  not added zstack */
		if comment == "" {
			continue
		}

		if commentCompare(comment, rule.comment) < 0 {
			break
		}
		num++;
	}

	rules = fmt.Sprintf("sudo iptables -t %s -I %s %d %s", FirewallTable, chainName, num, rules)
	cmd := Bash{
		Command: rules,
	}

	ret,_,_,err := cmd.RunWithReturn();
	if err != nil {
		log.Debugf("%s failed %s", rules, err.Error())
		return err
	}

	if ret != 0 {
		log.Debugf("%s failed ret = %d", rules, ret)
		return errors.Errorf("%s failed ret = %d", rules, ret)
	}

	return nil
}

/*
func GenerateNatRule(rule IptablesRule, ch Chain) string  {
	rules := strings.Join(rule.string(), " ")
	return fmt.Sprintf("-A %s %s", ch.string(), rules)
}*/

/* ipsec rules must at the head of all postrouting rules
  ipsec rules use InsertNatRule, other rules use append */
func InsertNatRule(rule IptablesRule, ch Chain)  error {
	rules := strings.Join(rule.string(), " ")
	if exist, _ := isExist(NatTable, ch.string(), rules); exist {
		log.Debugf("iptables %s %s already existed", NatTable, rules)
		return nil
	}

	olds, err := listRule(NatTable, ch.string())
	if err != nil {
		PanicOnError(fmt.Errorf("list iptables in %s faild %s", ch.string(), err.Error()))
		return err
	}

	num := 1
	for _, r := range olds {
		/* insert by comment order */
		comment := getCommentsFromRule(r)
		/* skip rules:  not added zstack */
		if comment == "" {
			continue
		}

		if commentCompare(comment, rule.comment) < 0 {
			break
		}
		num++;
	}

	rules = fmt.Sprintf("sudo iptables -t %s -I %s %d %s", NatTable, ch.string(), num, rules)
	cmd := Bash{
		Command: rules,
	}

	ret,_,_,err := cmd.RunWithReturn();
	if err != nil {
		log.Debugf("%s failed %s", rules, err.Error())
		return err
	}

	if ret != 0 {
		log.Debugf("%s failed ret = %d", rules, ret)
		return errors.Errorf("%s failed ret = %d", rules, ret)
	}

	return nil

}

func DeleteDNatRuleByComment(comment string) error {
	deleteIptablesRuleByComment(NatTable, PREROUTING.string(), comment)
	return nil
}

func DeleteSNatRuleByComment(comment string) error {
	deleteIptablesRuleByComment(NatTable, POSTROUTING.string(), comment)
	return nil
}

func DeleteLocalFirewallRuleByComment(nic string, comment string) error  {
	chainName := getChainName(nic, LOCAL)
	deleteIptablesRuleByComment(FirewallTable, chainName, comment)
	return nil
}

func DeleteFirewallRuleByComment(nic string, comment string) error {
	chainName := getChainName(nic, LOCAL)
	deleteIptablesRuleByComment(FirewallTable, chainName, comment)

	chainName = getChainName(nic, IN)
	deleteIptablesRuleByComment(FirewallTable, chainName, comment)

	return nil
}

func getDefaultIptablesRule() IptablesRule  {
	return IptablesRule {proto: "", src: "", dest: "", srcPort: 0, destPort: 0,
		states:nil, action: RETURN, comment:DefaultBottomRuleComment, inNic:"", outNic:""}
}

func DestroyNicFirewall(nic string)  {
	var rules []string
	var err error
	chainName := getChainName(nic, LOCAL)
	rules, err = listRule(FirewallTable, chainName)
	if (err == nil && len(rules) > 0) {
		for _, rule := range rules {
			deleteIptablesRule(FirewallTable, rule)
		}
	}
	r := fmt.Sprintf("sudo iptables -t %s -D INPUT -j %s", FirewallTable, chainName)
	cmd := Bash{
		Command: r,
	}

	ret,_,_,err := cmd.RunWithReturn();
	if err != nil {
		log.Debugf("%s failed %s", r, err.Error())
	}

	if ret != 0 {
		log.Debugf("%s failed ret = %d", r, ret)
	}


	chainName = getChainName(nic, IN)
	rules, err = listRule(FirewallTable, chainName)
	if (err == nil && len(rules) > 0) {
		for _, rule := range rules {
			deleteIptablesRule(FirewallTable, rule)
		}
	}
	r = fmt.Sprintf("sudo iptables -t %s -D FORWARD -j %s", FirewallTable, chainName)
	cmd = Bash{
		Command: r,
	}

	ret,_,_,err = cmd.RunWithReturn();
	if err != nil {
		log.Debugf("%s failed %s", r, err.Error())
	}

	if ret != 0 {
		log.Debugf("%s failed ret = %d", r, ret)
	}
}

func InitNicFirewall(nic string, ip string, pubNic bool, defaultAction string)  error {
	if err := initNicFireWallChain(nic); (err != nil) {
		log.Debugf("initNicFireWallChain failed %s", err.Error())
		return err
	}

	return initNicFirewallDefaultRules(nic, ip, pubNic, defaultAction)
}

func InitNatRule()  {
	if !IsSkipVyosIptables() {
		return
	}

	/*flush raw table to clear NOTRACK rule at startup*/
	cmd := Bash{
		Command: "sudo iptables -t raw -F",
	}

	cmd.Run(); cmd.PanicIfError()

	ch := PREROUTING
	if err := newChain(NatTable, "PREROUTING", ch.string(),  ""); err != nil {
		return
	}

	ch = POSTROUTING
	if err := newChain(NatTable, "POSTROUTING", ch.string(),  ""); err != nil {
		return
	}
}

func initNicFirewallDefaultRules(nic string, ip string, pubNic bool, defaultAction string) error {
	/* add rules for FORWARD chain */
	if pubNic {
		rule := getDefaultIptablesRule()
		rule.states = []string{RELATED, ESTABLISHED}
		rule.action = RETURN
		rule.comment = DefaultTopRuleComment
		if err := InsertFireWallRule(nic, rule, IN); err != nil {
			return err
		}
	} else {
		rule := getDefaultIptablesRule()
		rule.states = []string{INVALID, NEW, RELATED, ESTABLISHED}
		rule.action = RETURN
		rule.comment = DefaultTopRuleComment
		if err := InsertFireWallRule(nic, rule, IN); err != nil {
			return err
		}
	}

	rule := getDefaultIptablesRule()
	rule.proto = ICMP
	rule.action = RETURN
	rule.comment = DefaultTopRuleComment
	if err := InsertFireWallRule(nic, rule, IN); err != nil {
		return err
	}

	/* when this func is called in zvr, delete rules installed in zvrboot first */
	DeleteFirewallRuleByComment(nic, DefaultBottomRuleComment)

	rule = getDefaultIptablesRule()
	rule.states = []string {NEW}
	rule.action = RETURN
	rule.comment = DefaultBottomRuleComment
	if err := InsertFireWallRule(nic, rule, IN); err != nil{
		return err
	}

	rule = getDefaultIptablesRule()
	rule.action = defaultAction
	rule.comment = DefaultBottomRuleComment
	if err := InsertFireWallRule(nic, rule, IN); err != nil {
		return err
	}

	/* add rules for INPUT chain */
	rule = getDefaultIptablesRule()
	rule.dest = ip + "/32"
	rule.states = []string {RELATED, ESTABLISHED}
	rule.action = RETURN
	rule.comment = DefaultTopRuleComment
	if err := InsertFireWallRule(nic, rule, LOCAL); err != nil {
		return err
	}

	rule = getDefaultIptablesRule()
	rule.dest = ip + "/32"
	rule.proto = ICMP
	rule.action = RETURN
	rule.comment = DefaultTopRuleComment
	if err := InsertFireWallRule(nic, rule, LOCAL); err != nil {
		return err
	}

	if (pubNic) {
		rule = getDefaultIptablesRule()
		rule.dest = ip + "/32"
		rule.proto = TCP
		rule.destPort = 22
		rule.action = RETURN
		rule.comment = ManagementComment
		if err := InsertFireWallRule(nic, rule, LOCAL); err != nil {
			return err
		}

		rule = getDefaultIptablesRule()
		rule.dest = ip + "/32"
		rule.proto = TCP
		rule.destPort = 7272
		rule.action = RETURN
		rule.comment = ManagementComment
		if err := InsertFireWallRule(nic, rule, LOCAL); err != nil {
			return err
		}

	} else {
		rule = getDefaultIptablesRule()
		rule.dest = ip + "/32"
		rule.proto = TCP
		rule.destPort = 22
		rule.action = REJECT
		rule.comment = ManagementComment
		if err := InsertFireWallRule(nic, rule, LOCAL); err != nil {
			return err
		}
	}

	rule = getDefaultIptablesRule()
	rule.action = REJECT
	if err := InsertFireWallRule(nic, rule, LOCAL); err != nil {
		return err
	}

	return nil
}

func deleteIptablesRule(tableName, rule string) error {
	newRule := strings.Replace(rule, "-A", "-D", 1)
	r := fmt.Sprintf("sudo iptables -t %s %s", tableName, newRule)
	cmd := Bash{
		Command: r,
	}

	ret,_,_,err := cmd.RunWithReturn();
	if err != nil {
		log.Debugf("%s failed %s", r, err.Error())
		return err
	}

	if ret != 0 {
		log.Debugf("%s failed ret = %d", r, ret)
		return errors.Errorf("%s failed ret = %d", r, ret)
	}

	return nil
}

func deleteIptablesRuleByComment(tableName, chainName, comment string)  error {
	rules, _ := listRule(tableName, chainName)
	for _, rule := range rules {
		if strings.Contains(rule, comment) {
			newRule := strings.Replace(rule, "-A", "-D", 1)
			r := fmt.Sprintf("sudo iptables -t %s %s", tableName, newRule)
			cmd := Bash{
				Command: r,
			}

			ret,_,_,err := cmd.RunWithReturn();
			if err != nil {
				log.Debugf("%s failed %s", r, err.Error())
			}

			if ret != 0 {
				log.Debugf("%s failed ret = %d", r, ret)
			}
		}
	}

	return nil
}

func isExist(tableName, chainName string, rulespec ...string) (bool, error)  {
	rule := strings.Join(rulespec, " ")
	cmd := Bash{
		Command: fmt.Sprintf("sudo iptables -t %s -C %s %s", tableName, chainName, rule),
	}

	ret,_,_,err := cmd.RunWithReturn();
	if err != nil {
		log.Debugf("iptables table: %s chain: %s check %s failed %s", tableName, chainName, rule, err.Error())
		return false, err
	}

	if ret != 0 {
		log.Debugf("iptables table: %s chain: %s check %s failed ret = %d", tableName, chainName, rule, ret)
		return false, errors.Errorf("iptables table: %s chain: %s check %s failed ret = %d", tableName, chainName, rule, ret)
	}

	return true, nil
}

func initNicFireWallChain(nic string)  error{
	chainName := getChainName(nic, LOCAL)
	if err := newChain(FirewallTable, Predefined_local_chain, chainName,  nic); err != nil {
		return err
	}

	chainName = getChainName(nic, IN)
	if err := newChain(FirewallTable, Predefined_forward_chain, chainName, nic); err != nil {
		return err
	}

	return nil
}

func newChain(tableName, parentChain, chainName, nicName string) error {
	rule := fmt.Sprintf("sudo iptables -t %s -N %s", tableName, chainName)
	cmd := Bash{
		Command: rule,
	}

	ret,_,_,err := cmd.RunWithReturn();
	if err != nil {
		log.Debugf("%s failed %s", rule, err.Error())
		return err
	}

	if ret != 0 {
		log.Debugf("%s failed ret = %d",rule, ret)
		return errors.Errorf("%s failed ret = %d",rule, ret)
	}

	if nicName == "" {
		rule = fmt.Sprintf("sudo iptables -t %s -I %s -j %s", tableName, parentChain, chainName)
	} else {
		rule = fmt.Sprintf("sudo iptables -t %s -I %s -i %s -j %s", tableName, parentChain, nicName, chainName)
	}

	cmd = Bash{
		Command: rule,
	}

	ret,_,_,err = cmd.RunWithReturn();
	if err != nil {
		log.Debugf("%s failed %s", rule, err.Error())
		return err
	}

	if ret != 0 {
		log.Debugf("%s failed ret = %d", rule, ret)
		return errors.Errorf("%s failed ret = %d", rule, ret)
	}

	return nil
}

func listRule(tableName, chainName string) ([]string, error){
	rule := fmt.Sprintf("sudo iptables -t %s -S %s", tableName, chainName)
	cmd := Bash{
		Command: rule,
		NoLog: true,
	}

	ret,o,_,err := cmd.RunWithReturn();
	if err != nil {
		log.Debugf("%s failed %s", rule, err.Error())
		return nil, err
	}

	if ret != 0 {
		log.Debugf("%s failed ret = %d", rule, ret)
		return nil, errors.Errorf("%s failed ret = %d", rule, ret)
	}
	rules := strings.Split(o, "\n")

	// strip trailing newline
	if len(rules) > 0 && rules[len(rules)-1] == "" {
		rules = rules[:len(rules)-1]
	}

	return rules, nil
}

func getNatRuleSet() ([]string, []string, []string, error) {
	cmds := fmt.Sprintf("sudo iptables-save -t nat")
	cmd := Bash{
		Command: cmds,
		NoLog: true,
	}

	ret,o,_,err := cmd.RunWithReturn();
	if err != nil {
		log.Debugf("%s failed %s", cmds, err.Error())
		return nil, nil, nil, err
	}

	if ret != 0 {
		log.Debugf("%s failed ret = %d", cmds, ret)
		return nil, nil, nil, errors.Errorf("%s failed ret = %d", cmds, ret)
	}
	rules := strings.Split(o, "\n")

	// strip trailing newline
	if len(rules) > 0 && rules[len(rules)-1] == "" {
		rules = rules[:len(rules)-1]
	}

	snat := []string{}
	dnat := []string{}
	other := []string{}
	for _, r := range rules {
		fields := strings.Split(r, " ")
		if len(fields) <= 2 {
			other = append(other, r)
			continue
		}

		if fields[1] == PREROUTING.string(){
			dnat = append(dnat, r)
		} else if fields[1] == POSTROUTING.string() {
			snat = append(snat, r)
		} else {
			other = append(other, r)
		}
	}

	return snat, dnat, other, nil
}

func getFirewallRuleSet() ([]string, map[string][]string, error) {
	cmds := fmt.Sprintf("sudo iptables-save -t filter")
	cmd := Bash{
		Command: cmds,
		NoLog: true,
	}

	ret,o,_,err := cmd.RunWithReturn();
	if err != nil {
		log.Debugf("%s failed %s", cmds, err.Error())
		return nil, nil, err
	}

	if ret != 0 {
		log.Debugf("%s failed ret = %d", cmds, ret)
		return nil, nil, errors.Errorf("%s failed ret = %d", cmds, ret)
	}
	rules := strings.Split(o, "\n")

	// strip trailing newline
	if len(rules) > 0 && rules[len(rules)-1] == "" {
		rules = rules[:len(rules)-1]
	}

	zsRules := make(map[string][]string)
	other := []string{}
	for _, r := range rules {
		fields := strings.Split(r, " ")
		if len(fields) < 2 {
			other = append(other, r)
			continue
		}

		if fields[0] != "-A" {
			other = append(other, r)
			continue
		}

		if strings.Contains(fields[1], IN.string()) || strings.Contains(fields[1], LOCAL.string()) {
			zsRules[fields[1]] = append(zsRules[fields[1]], r)
		} else {
			other = append(other, r)
		}
	}

	return other, zsRules, nil
}

func insertRuleIntoBuffer(ruleset []string, rules []IptablesRule, comment, chainName string) []string {
	temp := []string{}
	added := false
	for _, r := range ruleset {
		c := getCommentsFromRule(r)

		if commentCompare(c, comment) < 0 && added == false {
			for _, rule := range rules {
				rules := fmt.Sprintf("-A %s %s", chainName, strings.Join(rule.string(), " "))
				temp = append(temp, rules)
			}
			added = true
		}
		temp = append(temp, r)
	}

	if !added {
		for _, rule := range rules {
			rules := fmt.Sprintf("-A %s %s", chainName, strings.Join(rule.string(), " "))
			temp = append(temp, rules)
		}
	}

	return temp
}

func restoreIptablesRulesSet(ruleSet []string, tableName string) error  {
	tmpFile, err := ioutil.TempFile(os.TempDir(), "iptable-restore")
	if err != nil {
		log.Debugf("create iptable-restore temp file failed %s", err.Error())
		return err
	}

	// Remember to clean up the file afterwards
	defer os.Remove(tmpFile.Name())

	content := strings.Join(ruleSet, "\n")
	if _, err = tmpFile.Write([]byte(content)); err != nil {
		log.Debugf("write to temp file failed %s, rules: %s", content, err.Error())
		return err
	}

	// Close the file
	if err := tmpFile.Close(); err != nil {
		log.Debugf("close temp file failed %s", err.Error())
		return err
	}

	cmds := fmt.Sprintf("sudo iptables-restore  --table=%s < %s", tableName, tmpFile.Name())
	cmd := Bash{
		Command: cmds,
	}

	_,_,_,err = cmd.RunWithReturn();
	if err != nil {
		log.Debugf("%s failed %s", cmds, err.Error())
		return err
	}

	return nil
}

func removeRules(rules []string, comment string) []string {
	temp := []string{}
	for _, r := range rules {
		if !strings.Contains(r, comment) {
			temp = append(temp, r)
		}
	}

	return temp
}

/* 1. splits nat rules: into 3 groups: zs.snat, zs.dnat， other
   2. remove to be synced type
   3. add synced rules into zs.snat or zs.dnat
   4. assemble zs.snat, zs.dnat into other */

func SyncNatRule(snatRules, dnatRules []IptablesRule, comment string) error {
	/* #1 */
	snat, dnat, other, _ := getNatRuleSet()

	/* #2 */
	snat = removeRules(snat, comment)
	dnat = removeRules(dnat, comment)

	/* #3 */
	dnat = insertRuleIntoBuffer(dnat, dnatRules, comment, PREROUTING.string())
	snat = insertRuleIntoBuffer(snat, snatRules, comment, POSTROUTING.string())

	/* $4, last 2 in other is "
		COMMIT
		# Completed on Wed Mar 13 19:37:47 2019
	*/
	temp := []string{}
	temp = append(temp, other[:len(other) -2]...)
	temp = append(temp, dnat...)
	temp = append(temp, snat...)
	temp = append(temp, other[len(other)-2:]...)

	return restoreIptablesRulesSet(temp, NatTable)
}

/* 1. splits nat rules: into 2 groups: a map include all configured filters， and other
   2. remove to be synced type
   3. add synced rules into zs.snat or zs.dnat
   4. assemble zs.snat, zs.dnat into other */
func SyncFirewallRule(rulesMap map[string][]IptablesRule, comment string, ch Chain) error {
	/* #1 */
	other, filtersMap, _ := getFirewallRuleSet()

	/* #2 */
	for chainName, filters := range filtersMap {
		filtersMap[chainName] = removeRules(filters, comment)
	}

	/* #3 */
	for nicname, rules := range rulesMap {
		chainName := getChainName(nicname, ch)
		if _, ok := filtersMap[chainName]; !ok {
			filtersMap[chainName] = []string{}
		}

		filtersMap[chainName] = insertRuleIntoBuffer(filtersMap[chainName], rules, comment, chainName)
	}

	/* $4, last 2 in other is "
		COMMIT
		# Completed on Wed Mar 13 19:37:47 2019
	*/
	chainNames := []string{}
	for chainName, _ := range filtersMap {
		chainNames = append(chainNames, chainName)
	}
	sort.Strings(chainNames)

	temp := []string{}
	temp = append(temp, other[:len(other) -2]...)
	for _, name := range chainNames {
		temp = append(temp, filtersMap[name]...)
	}
	temp = append(temp, other[len(other) -2:]...)

	return restoreIptablesRulesSet(temp, FirewallTable)
}

/* 1. splits nat rules: into 2 groups: a map include all configured filters， and other
   2. remove to be synced type
   3. add synced rules into zs.snat or zs.dnat
   4. assemble zs.snat, zs.dnat into other */
func SyncLocalAndInFirewallRule(rulesMap, localRulesMap map[string][]IptablesRule, comment string) error {
	/* #1 */
	other, filtersMap, _ := getFirewallRuleSet()

	/* #2 */
	for chainName, filters := range filtersMap {
		filtersMap[chainName] = removeRules(filters, comment)
	}

	/* #3, ipsec forward rule */
	for nicname, rules := range rulesMap {
		chainName := getChainName(nicname, IN)
		if _, ok := filtersMap[chainName]; !ok {
			filtersMap[chainName] = []string{}
		}

		filtersMap[chainName] = insertRuleIntoBuffer(filtersMap[chainName], rules, comment, chainName)
	}

	/* #3, ipsec local rule */
	for nicname, rules := range localRulesMap {
		chainName := getChainName(nicname, LOCAL)
		if _, ok := filtersMap[chainName]; !ok {
			filtersMap[chainName] = []string{}
		}

		filtersMap[chainName] = insertRuleIntoBuffer(filtersMap[chainName], rules, comment, chainName)
	}

	/* $4, last 2 in other is "
		COMMIT
		# Completed on Wed Mar 13 19:37:47 2019
	*/
	chainNames := []string{}
	for chainName, _ := range filtersMap {
		chainNames = append(chainNames, chainName)
	}
	sort.Strings(chainNames)

	temp := []string{}
	temp = append(temp, other[:len(other) -2]...)
	for _, name := range chainNames {
		temp = append(temp, filtersMap[name]...)
	}
	temp = append(temp, other[len(other) -2:]...)

	return restoreIptablesRulesSet(temp, FirewallTable)
}
