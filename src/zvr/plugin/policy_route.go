package plugin

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"strconv"
	"strings"
	"zvr/server"
	"zvr/utils"
)

const (
	SYNC_POLICY_ROUTE        = "/policyroute/sync"
	POLICY_ROUTE_TABLE_FILE  = "/etc/iproute2/rt_tables"
	POLICY_ROUTE_TABLE_FILE_TEMP  = "/tmp/.zs_rt_tables"
	POLICY_ROUTE_COMMENT     = "Zs-Pr-Rules"
	POLICY_ROUTE_COMMENT_DEFAULT     = "Zs-Pr-Default-Rules"
	IPTABLES_MANGLE          = "sudo iptables -t mangle -m comment --comment " + POLICY_ROUTE_COMMENT + " "
	IPTABLES_MANGLE_DELETE   = "sudo iptables -t mangle "
	POLICY_ROUTE_TABLE_CHAIN = "zs-rt-"
	POLICY_ROUTE_RULE_CHAIN  = "zs-rule-"
	VYOSHA_POLICY_ROUTE_SCRIPT = "/home/vyos/zvr/keepalived/script/policyRoutes.sh"
)

var DEFAULT_ROUTE_TABLE []string

type policyRuleSetInfo struct {
	RuleSetName string `json:"ruleSetName"`
	System bool `json:"system"`
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
	OutNicMic string `json:"outNicMic"`
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

func getPolicyRouteSetName(rulesetName string) string  {
	return fmt.Sprintf("%s%s", POLICY_ROUTE_RULE_CHAIN, rulesetName)
}

func getPolicyRouteTableName(tableId int) string  {
	return fmt.Sprintf("%s%d", POLICY_ROUTE_TABLE_CHAIN, tableId)
}

func syncPolicyRoute(ctx *server.CommandContext) interface{} {
	cmd := &syncPolicyRouteCmd{}
	ctx.GetCommand(cmd)
	deletePolicyRoutes()
	applyPolicyRoutes(cmd)
	return nil
}

func deleteIpRules()  {
	/* vyos@vyos:~$ ip rule | grep zs-rt
	32759:	from 10.86.0.0/23 lookup zs-rt-181
	32760:	from all fwmark b5 lookup zs-rt-181
	32761:	from all fwmark 0xb4 lookup zs-rt-180
	32762:	from all fwmark 0xb5 lookup zs-rt-181
	32763:	from all fwmark 0xb4 lookup zs-rt-180
	32764:	from all fwmark 0xb5 lookup zs-rt-181
	32765:	from all fwmark 0xb4 lookup zs-rt-180
	*/
	bash := utils.Bash {
		Command: fmt.Sprintf("ip rule | grep '%s'", POLICY_ROUTE_TABLE_CHAIN),
	}
	_, o, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
	if o != "" {
		lines := strings.Split(o, "\n")
		var newCmds []string
		for _, line := range lines {
			if line == "" {
				continue
			}

			if strings.Contains(line, "fwmark") {
				items := strings.Fields(line)
				tableId, _ := strconv.ParseInt(strings.Replace(strings.TrimSpace(items[4]), "0x", "", 1), 16, 64)
				newCmd := fmt.Sprintf("ip rule del fwmark %d table %d", tableId, tableId)
				newCmds = append(newCmds, newCmd)
			} else {
				items := strings.Fields(line)
				tables := strings.Split(items[4], "-")
				tableId, _ := strconv.ParseInt(strings.TrimSpace(tables[2]), 10, 64)
				newCmd := fmt.Sprintf("ip rule del from %s table %d", items[2], tableId)
				newCmds = append(newCmds, newCmd)
			}
		}
		bash = utils.Bash {
			Command: strings.Join(newCmds, ";"),
		}
		_, _, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
	}
}

func deletePolicyRoutes()  {
	/* delete mangle rule: all policy route tables has comments: ZS-PR-RULES */
	bash := utils.Bash {
		Command: fmt.Sprintf("sudo iptables-save -t mangle | grep '%s'", POLICY_ROUTE_COMMENT),
	}
	_, o, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
	if o != "" {
		lines := strings.Split(o, "\n")
		var newCmds []string
		for _, line := range lines {
			newCmd := strings.Replace(line, "-A ", "-D ", 1)
			newCmds = append(newCmds, IPTABLES_MANGLE_DELETE + newCmd)
		}
		bash = utils.Bash {
			Command: strings.Join(newCmds, ";"),
		}
		_, _, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
	}

	/* delete mangle table chain: all policy route chain name has prefix: zs-rt-, or zs-rule- */
	bash = utils.Bash {
		Command: fmt.Sprintf("sudo iptables-save -t mangle | grep ':' | grep '%s' | awk '{print $1}'", POLICY_ROUTE_RULE_CHAIN),
	}
	_, o, _, err = bash.RunWithReturn(); utils.PanicOnError(err)
	if o != "" {
		lines := strings.Split(o, "\n")
		var newCmds []string
		for _, line := range lines {
			newCmd := strings.Replace(line, ":", "", 1)
			newCmds = append(newCmds, "sudo iptables -t mangle -X " + newCmd)
		}
		bash = utils.Bash {
			Command: strings.Join(newCmds, ";"),
		}
		_, _, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
	}

	bash = utils.Bash {
		Command: fmt.Sprintf("sudo iptables-save -t mangle | grep ':' | grep '%s' | awk '{print $1}'", POLICY_ROUTE_TABLE_CHAIN),
	}
	_, o, _, err = bash.RunWithReturn(); utils.PanicOnError(err)
	if o != "" {
		lines := strings.Split(o, "\n")
		var newCmds []string
		for _, line := range lines {
			if line == "" {
				continue
			}
			newCmd := strings.Replace(line, ":", "", 1)
			newCmds = append(newCmds, "sudo iptables -t mangle -X " + newCmd)
		}
		bash = utils.Bash {
			Command: strings.Join(newCmds, ";"),
		}
		_, _, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
	}

	/* remove policy route entry, tableId in /etc/iproute2/rt_tables:  100 zs-rt-100
	   get tableId for this file, then delete all entries in table
	*/
	bash = utils.Bash {
		Command: fmt.Sprintf("sudo grep '%s' %s | awk '{print $1}'", POLICY_ROUTE_TABLE_CHAIN, POLICY_ROUTE_TABLE_FILE),
	}
	_, o, _, err = bash.RunWithReturn(); utils.PanicOnError(err)
	if o != "" {
		lines := strings.Split(o, "\n")
		var newCmds []string
		for _, line := range lines {
			if line == "" {
				continue
			}
			newCmds = append(newCmds, fmt.Sprintf("ip route flush  table %s", line))
		}
		bash = utils.Bash {
			Command: strings.Join(newCmds, ";"),
		}
		_, _, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
	}

	deleteIpRules()
}

func createPolicyRouteTables(tableIds []int) error {
	routeTablesCmds := []string{}
	for _, rt := range tableIds {
		routeTablesCmds = append(routeTablesCmds, fmt.Sprintf("sudo ip route flush table %d", rt))
		routeTablesCmds = append(routeTablesCmds, fmt.Sprintf("ip rule add fwmark %d table %d", rt, rt))
	}
	routeTablesCmd := strings.Join(routeTablesCmds, ";")
	bash := utils.Bash {
		Command: routeTablesCmd,
	}
	ret, _, _, err := bash.RunWithReturn()
	if err != nil {
		return err
	}

	if ret != 0 {
		return fmt.Errorf("create iptable mark rule for route table: %s, ret: %d", routeTablesCmd, ret)
	}

	return nil
}

func createPolicyRouteTableEntry(routes []policyRouteInfo) error {
	routeTablesCmds := []string{}
	for _, route := range routes {
		if route.OutNicMic != "" {
			nicName, err := utils.GetNicNameByMac(route.OutNicMic);utils.PanicOnError(err)
			routeTablesCmds = append(routeTablesCmds, fmt.Sprintf("ip route add %s dev %s table %d",
				route.DestinationCidr, nicName, route.TableNumber))
		} else {
			routeTablesCmds = append(routeTablesCmds, fmt.Sprintf("ip route add %s metric %d via %s table %d",
				route.DestinationCidr, route.Distance, route.NextHopIp, route.TableNumber))
		}
	}
	routeTablesCmd := strings.Join(routeTablesCmds, ";")
	bash := utils.Bash {
		Command: routeTablesCmd,
	}

	writePolicyRouteHaScript(routeTablesCmd)
	if IsMaster() {
		ret, _, _, err := bash.RunWithReturn()
		if err != nil {
			return err
		}
		if ret != 0 {
			return fmt.Errorf("add policy route entry command: %s, ret: %d", routeTablesCmd, ret)
		}
	}

	return nil
}

func createPolicyRouteRuleSet(RuleSets []policyRuleSetInfo) (error, map[string]bool) {
	rsMap := map[string]bool{}
	chainCmds := []string{}
	for _, rs := range RuleSets {
		rsMap[rs.RuleSetName] = rs.System
		psName := getPolicyRouteSetName(rs.RuleSetName)
		chainCmds = append(chainCmds, fmt.Sprintf("sudo iptables -t mangle -N %s", psName))
	}
	chainCmd := strings.Join(chainCmds, ";")
	bash := utils.Bash {
		Command: chainCmd,
	}
	ret, _, _, err := bash.RunWithReturn()
	if err != nil {
		return err, nil
	}

	if ret != 0 {
		return fmt.Errorf("create iptable chain command: %s, ret: %d", chainCmd, ret), nil
	}

	return nil, rsMap
}

func createPolicyRouteL3Ref(l3Refs []policyRuleSetNicRef, rsMap map[string]bool) error {
	var nicCmds []string
	for _, ref := range l3Refs {
		nicname, err := utils.GetNicNameByMac(ref.Mac);utils.PanicOnError(err)
		psName := getPolicyRouteSetName(ref.RuleSetName)
		nicCmds = append(nicCmds, fmt.Sprintf(IPTABLES_MANGLE + " -A PREROUTING -i %s -j %s", nicname, psName))

		/* system rule set, add  */
		if rsMap[ref.RuleSetName] {
			/* rule set name like this: ZS-PR-RS-181, last number is table id */
			items := strings.Split(ref.RuleSetName, "-")
			nicCmds = append(nicCmds, fmt.Sprintf(IPTABLES_MANGLE + " -A %s -m mark --mark 0 -j MARK --set-mark %s", psName, items[len(items) -1]))
			nicCmds = append(nicCmds, fmt.Sprintf(IPTABLES_MANGLE + " -A %s -j CONNMARK --set-mark %s", psName, items[len(items) -1]))
		}
	}
	nicCmd := strings.Join(nicCmds, ";")
	bash := utils.Bash {
		Command: nicCmd,
	}
	ret, _, _, err := bash.RunWithReturn()
	if err != nil {
		return err
	}

	if ret != 0 {
		return fmt.Errorf("add mangle table command for policy route l3Ref: %s, ret: %d", nicCmd, ret)
	}

	return nil
}

func createPolicyRouteRules(rules []policyRuleInfo, rsMap map[string]bool) error {
	ruleCmds := []string{}
	for _, rule := range rules {
		if rule.State == "disable" {
			continue
		}

		if rsMap[rule.RuleSetName] {
			/* rule.RuleNumber */
			cmd := fmt.Sprintf("ip rule add from %s table %d", rule.SourceIp, rule.TableNumber)
			ruleCmds = append(ruleCmds, cmd)
			continue
		}

		cmd := IPTABLES_MANGLE + " -A " + getPolicyRouteSetName(rule.RuleSetName)
		if rule.SourceIp != "" {
			cmd += " -s " + rule.SourceIp
		}
		if rule.DestIp != "" {
			cmd += " -s " + rule.SourceIp
		}
		if rule.Protocol != "" {
			cmd += " -p " + rule.Protocol
		}
		if rule.SourcePort != "" || rule.DestPort != "" {
			cmd += " -m " + rule.Protocol
		}
		if rule.SourcePort != "" {
			cmd += " --sport " + rule.SourcePort
		}
		if rule.DestPort != "" {
			cmd += " --dport " + rule.DestPort
		}
		if rule.TableNumber != 0 {
			cmd += " -j " + getPolicyRouteTableName(rule.TableNumber)
		}
		/* rule.RuleNumber */
		ruleCmds = append(ruleCmds, cmd)
	}
	ruleCmd := strings.Join(ruleCmds, ";")
	bash := utils.Bash {
		Command: ruleCmd,
	}
	ret, _, _, err := bash.RunWithReturn()
	if err != nil {
		return err
	}
	if ret != 0 {
		return fmt.Errorf("add mangle rule command: %s, ret: %d", ruleCmd, ret)
	}

	return nil
}

func applyPolicyRoutes(cmd *syncPolicyRouteCmd)  {
	routeTablesCmds := DEFAULT_ROUTE_TABLE
	for _, rt := range cmd.TableNumbers {
		routeTablesCmds = append(routeTablesCmds, fmt.Sprintf("%d %s%d", rt, POLICY_ROUTE_TABLE_CHAIN, rt))
	}
	rtCmd := strings.Join(routeTablesCmds, "\n")
	err := ioutil.WriteFile(POLICY_ROUTE_TABLE_FILE_TEMP, []byte(rtCmd), 0755); utils.PanicOnError(err)
	bash := utils.Bash {
		Command: fmt.Sprintf("sudo mv %s %s", POLICY_ROUTE_TABLE_FILE_TEMP, POLICY_ROUTE_TABLE_FILE),
	}
	_, _, _, err = bash.RunWithReturn(); utils.PanicOnError(err)

	/* route table */
	if cmd.TableNumbers != nil {
		err := createPolicyRouteTables(cmd.TableNumbers);utils.PanicOnError(err)
	}

	/* route table entry */
	if cmd.Routes != nil {
		err := createPolicyRouteTableEntry(cmd.Routes);utils.PanicOnError(err)
	}

	/* ruleset */
	var rsMap map[string]bool
	if cmd.RuleSets != nil {
		err, rsMap = createPolicyRouteRuleSet(cmd.RuleSets);utils.PanicOnError(err)
	}

	/* L3 ref */
	if cmd.Refs != nil {
		err := createPolicyRouteL3Ref(cmd.Refs, rsMap);utils.PanicOnError(err)
	}

	/* policy rules */
	if cmd.Rules != nil {
		err := createPolicyRouteRules(cmd.Rules, rsMap);utils.PanicOnError(err)
	}
}

func init ()  {
	DEFAULT_ROUTE_TABLE = []string {
		"#",
		"# reserved values",
		"#",
		"255	local",
		"254	main",
		"253	default",
		"0	unspec",
	    "#",
	    "# local",
	    "#",
	    "#1	inr.ruhep"}
}

func writePolicyRouteHaScript(routes string)  {
	if !utils.IsHaEabled() {
		return
	}

	err := ioutil.WriteFile(VYOSHA_POLICY_ROUTE_SCRIPT, []byte(routes), 0755); utils.PanicOnError(err)
}

func initSystemMangleTable()  {
	var cmds []string
	cmds = append(cmds, fmt.Sprintf("sudo iptables-save -t mangle | grep '%s'", POLICY_ROUTE_COMMENT_DEFAULT))
	cmds = append(cmds, fmt.Sprintf("|| (sudo iptables -t mangle -m comment --comment '%s' -A PREROUTING -j CONNMARK --restore-mark;", POLICY_ROUTE_COMMENT_DEFAULT))
	cmds = append(cmds, fmt.Sprintf("sudo iptables -t mangle -m comment --comment '%s' -A PREROUTING -m mark ! --mark 0 -j ACCEPT)", POLICY_ROUTE_COMMENT_DEFAULT))
	bash := utils.Bash {
		Command: strings.Join(cmds, " "),
		NoLog: true,
	}
	_, _, _, err := bash.RunWithReturn()
	if err != nil {
		log.Debugf("!!!init iptables mangle table failed because %s!!!", err)
		return
	}
}

func PolicyRouteEntryPoint()  {
	initSystemMangleTable()
	server.RegisterAsyncCommandHandler(SYNC_POLICY_ROUTE, server.VyosLock(syncPolicyRoute))
}