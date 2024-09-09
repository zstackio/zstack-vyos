package utils

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("vyosIptables_test", func() {

	It("preparing vyosIptables_test parse", func() {
		InitLog(GetVyosUtLogDir()+"vyosIptables-test.log", IsRuingUT())
		SetSkipVyosIptablesForUT(true)
	})

	It("vyosIptables_test InitVyattaFilterTable", func() {
		/* default filter table:
		      *filter
		   :INPUT ACCEPT [0:0]
		   :FORWARD ACCEPT [0:0]
		   :OUTPUT ACCEPT [0:0]
		   :VYATTA_POST_FW_FWD_HOOK - [0:0]
		   :VYATTA_POST_FW_IN_HOOK - [0:0]
		   :VYATTA_POST_FW_OUT_HOOK - [0:0]
		   :VYATTA_PRE_FW_FWD_HOOK - [0:0]
		   :VYATTA_PRE_FW_IN_HOOK - [0:0]
		   :VYATTA_PRE_FW_OUT_HOOK - [0:0]
		   -A INPUT -j VYATTA_PRE_FW_IN_HOOK
		   -A INPUT -j VYATTA_POST_FW_IN_HOOK
		   -A FORWARD -j VYATTA_PRE_FW_FWD_HOOK
		   -A FORWARD -j VYATTA_POST_FW_FWD_HOOK
		   -A OUTPUT -j VYATTA_PRE_FW_OUT_HOOK
		   -A OUTPUT -j VYATTA_POST_FW_OUT_HOOK
		   -A VYATTA_POST_FW_FWD_HOOK -j ACCEPT
		   -A VYATTA_POST_FW_IN_HOOK -j ACCEPT
		   -A VYATTA_POST_FW_OUT_HOOK -j ACCEPT
		   -A VYATTA_PRE_FW_FWD_HOOK -j RETURN
		   -A VYATTA_PRE_FW_IN_HOOK -j RETURN
		   -A VYATTA_PRE_FW_OUT_HOOK -j RETURN
		   COMMIT*/
		table := NewIpTables(FirewallTable)

		cnames := []string{"INPUT", "FORWARD", "OUTPUT", "VYATTA_POST_FW_FWD_HOOK", "VYATTA_POST_FW_IN_HOOK",
			"VYATTA_POST_FW_OUT_HOOK", "VYATTA_PRE_FW_FWD_HOOK", "VYATTA_PRE_FW_IN_HOOK", "VYATTA_PRE_FW_OUT_HOOK"}
		for _, name := range cnames {
			res := table.CheckChain(name)
			Expect(res).To(BeTrue(), fmt.Sprintf("chain %s parse failed", name))
		}

		var rules []*IpTableRule
		rule := NewIpTableRule("INPUT").SetAction("VYATTA_PRE_FW_IN_HOOK")
		rules = append(rules, rule)
		rule = NewIpTableRule("INPUT").SetAction("VYATTA_POST_FW_IN_HOOK")
		rules = append(rules, rule)
		rule = NewIpTableRule("FORWARD").SetAction("VYATTA_PRE_FW_FWD_HOOK")
		rules = append(rules, rule)
		rule = NewIpTableRule("FORWARD").SetAction("VYATTA_POST_FW_FWD_HOOK")
		rules = append(rules, rule)
		rule = NewIpTableRule("OUTPUT").SetAction("VYATTA_PRE_FW_OUT_HOOK")
		rules = append(rules, rule)
		rule = NewIpTableRule("OUTPUT").SetAction("VYATTA_POST_FW_OUT_HOOK")
		rules = append(rules, rule)
		rule = NewIpTableRule("VYATTA_POST_FW_FWD_HOOK").SetAction("ACCEPT")
		rules = append(rules, rule)
		rule = NewIpTableRule("VYATTA_POST_FW_IN_HOOK").SetAction("ACCEPT")
		rules = append(rules, rule)
		rule = NewIpTableRule("VYATTA_POST_FW_OUT_HOOK").SetAction("ACCEPT")
		rules = append(rules, rule)
		rule = NewIpTableRule("VYATTA_PRE_FW_FWD_HOOK").SetAction("RETURN")
		rules = append(rules, rule)
		rule = NewIpTableRule("VYATTA_PRE_FW_IN_HOOK").SetAction("RETURN")
		rules = append(rules, rule)
		rule = NewIpTableRule("VYATTA_PRE_FW_OUT_HOOK").SetAction("RETURN")
		rules = append(rules, rule)

		for _, r := range rules {
			res := table.Check(r)
			Expect(res).To(BeTrue(), fmt.Sprintf("rule %s parse failed", r))
		}

		InitVyattaFilterTable()
		table = NewIpTables(FirewallTable)
		cnames = append(cnames, VYOS_INPUT_ROOT_CHAIN)
		cnames = append(cnames, VYOS_FWD_ROOT_CHAIN)
		cnames = append(cnames, VYOS_FWD_OUT_ROOT_CHAIN)

		rule = NewIpTableRule("INPUT").SetAction(VYOS_INPUT_ROOT_CHAIN)
		rules = append(rules, rule)
		rule = NewIpTableRule("FORWARD").SetAction(VYOS_FWD_ROOT_CHAIN)
		rules = append(rules, rule)
		rule = NewIpTableRule("FORWARD").SetAction(VYOS_FWD_OUT_ROOT_CHAIN)
		rules = append(rules, rule)
		for _, name := range cnames {
			res := table.CheckChain(name)
			Expect(res).To(BeTrue(), fmt.Sprintf("chain %s parse failed", name))
		}
		for _, r := range rules {
			res := table.Check(r)
			Expect(res).To(BeTrue(), fmt.Sprintf("rule %s parse failed", r))
		}

		/* there 3 rule in input chains, VYATTA_FW_LOCAL_HOOK should be the second one */
		inputRules := table.Found(INPUT.String(), "")
		Expect(len(inputRules) == 3).To(BeTrue(), fmt.Sprintf("input chain rule number[%d] should be 3 ", len(inputRules)))
		seq := 0
		for i, r := range inputRules {
			if r.action == VYOS_INPUT_ROOT_CHAIN {
				seq = i
			}
		}
		Expect(seq == 1).To(BeTrue(), fmt.Sprintf("vyos input chain should be the second rule"))

		/* call this api again */
		InitVyattaFilterTable()
		table = NewIpTables(FirewallTable)
		for _, name := range cnames {
			res := table.CheckChain(name)
			Expect(res).To(BeTrue(), fmt.Sprintf("chain %s parse failed", name))
		}
		for _, r := range rules {
			res := table.Check(r)
			Expect(res).To(BeTrue(), fmt.Sprintf("rule %s parse failed", r))
		}
	})

	It("vyosIptables_test InitNicFirewall", func() {
		err := InitNicFirewall(PrivateNicsForUT[0].Name, PrivateNicsForUT[0].Ip, false, "REJECT")
		Expect(err).To(BeNil(), fmt.Sprintf("init nic firewall for interface[%s] failed", PrivateNicsForUT[0].Name))

		table := NewIpTables(FirewallTable)
		var cnames []string
		localChain := GetRuleSetName(PrivateNicsForUT[0].Name, RULESET_LOCAL)
		forwardChain := GetRuleSetName(PrivateNicsForUT[0].Name, RULESET_IN)
		outChain := GetRuleSetName(PrivateNicsForUT[0].Name, RULESET_OUT)
		cnames = append(cnames, localChain)
		cnames = append(cnames, forwardChain)
		cnames = append(cnames, outChain)
		for _, name := range cnames {
			res := table.CheckChain(name)
			Expect(res).To(BeTrue(), fmt.Sprintf("chain %s check failed", name))
		}

		var rules []*IpTableRule
		rule := NewIpTableRule(VYOS_INPUT_ROOT_CHAIN)
		rule.SetAction(localChain).SetInNic(PrivateNicsForUT[0].Name)
		rules = append(rules, rule)

		rule = NewIpTableRule(VYOS_FWD_ROOT_CHAIN)
		rule.SetAction(forwardChain).SetInNic(PrivateNicsForUT[0].Name)
		rules = append(rules, rule)

		rule = NewIpTableRule(VYOS_FWD_OUT_ROOT_CHAIN)
		rule.SetAction(outChain).SetOutNic(PrivateNicsForUT[0].Name)
		rules = append(rules, rule)

		/* 3 default rules in forward chain of private nic */
		rule = NewIpTableRule(forwardChain)
		rule.SetAction(IPTABLES_ACTION_RETURN).SetComment(SystemTopRule)
		rule.SetState([]string{IPTABLES_STATE_RELATED, IPTABLES_STATE_ESTABLISHED})
		rules = append(rules, rule)

		rule = NewDefaultIpTableRule(forwardChain, IPTABLES_RULENUMBER_9999)
		rule.SetAction(IPTABLES_ACTION_RETURN)
		rules = append(rules, rule)

		rule = NewDefaultIpTableRule(forwardChain, IPTABLES_RULENUMBER_MAX)
		rule.SetAction("REJECT")
		rules = append(rules, rule)

		/* 4 default rules in local chain of private nic */
		rule = NewIpTableRule(localChain)
		rule.SetAction(IPTABLES_ACTION_RETURN).SetComment(SystemTopRule)
		rule.SetDstIp(PrivateNicsForUT[0].Ip + "/32").SetState([]string{IPTABLES_STATE_RELATED, IPTABLES_STATE_ESTABLISHED})
		rules = append(rules, rule)

		rule = NewIpTableRule(localChain)
		rule.SetAction(IPTABLES_ACTION_RETURN).SetComment(SystemTopRule)
		rule.SetDstIp(PrivateNicsForUT[0].Ip + "/32").SetProto(IPTABLES_PROTO_ICMP)
		rules = append(rules, rule)

		rule = NewIpTableRule(localChain)
		rule.SetAction(IPTABLES_ACTION_REJECT).SetRejectType(REJECT_TYPE_ICMP_UNREACHABLE)
		rule.SetComment(SystemTopRule).SetDstIp(PrivateNicsForUT[0].Ip + "/32").SetProto(IPTABLES_PROTO_TCP).SetDstPort("22")
		rules = append(rules, rule)

		rule = NewDefaultIpTableRule(localChain, IPTABLES_RULENUMBER_MAX)
		rule.SetAction("REJECT")
		rules = append(rules, rule)

		for _, r := range rules {
			res := table.Check(r)
			Expect(res).To(BeTrue(), fmt.Sprintf("rule %s check failed", r))
		}

		/* call InitNicFirewall again */
		err = InitNicFirewall(PrivateNicsForUT[0].Name, PrivateNicsForUT[0].Ip, false, "REJECT")
		Expect(err).To(BeNil(), fmt.Sprintf("init nic firewall for interface[%s] failed", PrivateNicsForUT[0].Name))

		table = NewIpTables(FirewallTable)
		for _, name := range cnames {
			res := table.CheckChain(name)
			Expect(res).To(BeTrue(), fmt.Sprintf("chain %s check failed", name))
		}
		for _, r := range rules {
			res := table.Check(r)
			Expect(res).To(BeTrue(), fmt.Sprintf("rule %s check failed", r))
		}

		/* change default action */
		err = SetNicDefaultFirewallRule(PrivateNicsForUT[0].Name, "ACCEPT")
		Expect(err).To(BeNil(), fmt.Sprintf("change nic :%s firewall default action failed ", PrivateNicsForUT[0].Name))

		var defaultRules []*IpTableRule
		rule = NewDefaultIpTableRule(forwardChain, IPTABLES_RULENUMBER_MAX)
		rule.SetAction("ACCEPT")
		rules = append(defaultRules, rule)
		rule = NewDefaultIpTableRule(forwardChain, IPTABLES_RULENUMBER_MAX)
		rule.SetAction("ACCEPT")
		rules = append(defaultRules, rule)
		table = NewIpTables(FirewallTable)
		for _, r := range rules {
			res := table.Check(r)
			Expect(res).NotTo(BeTrue(), fmt.Sprintf("rule %s check failed", r))
		}

		/* change default action again */
		err = SetNicDefaultFirewallRule(PrivateNicsForUT[0].Name, "DROP")
		Expect(err).To(BeNil(), fmt.Sprintf("change nic :%s firewall default action failed ", PrivateNicsForUT[0].Name))

		defaultRules = []*IpTableRule{}
		rule = NewDefaultIpTableRule(forwardChain, IPTABLES_RULENUMBER_MAX)
		rule.SetAction("DROP")
		rules = append(defaultRules, rule)
		rule = NewDefaultIpTableRule(forwardChain, IPTABLES_RULENUMBER_MAX)
		rule.SetAction("DROP")
		rules = append(defaultRules, rule)
		table = NewIpTables(FirewallTable)
		for _, r := range rules {
			res := table.Check(r)
			Expect(res).NotTo(BeTrue(), fmt.Sprintf("rule %s check failed", r))
		}

		/* destroy nic default rules */
		err = DestroyNicFirewall(PrivateNicsForUT[0].Name)
		Expect(err).To(BeNil(), fmt.Sprintf("destory nic firewall for interface[%s] failed", PrivateNicsForUT[0].Name))
		table = NewIpTables(FirewallTable)
		for _, name := range cnames {
			res := table.CheckChain(name)
			Expect(res).NotTo(BeTrue(), fmt.Sprintf("chain %s check failed", name))
		}
		for _, r := range rules {
			res := table.Check(r)
			Expect(res).NotTo(BeTrue(), fmt.Sprintf("rule %s check failed", r))
		}

		err = DestroyNicFirewall(PrivateNicsForUT[0].Name)
		Expect(err).To(BeNil(), fmt.Sprintf("destory nic firewall for interface[%s] failed", PrivateNicsForUT[0].Name))
		table = NewIpTables(FirewallTable)
		for _, name := range cnames {
			res := table.CheckChain(name)
			Expect(res).NotTo(BeTrue(), fmt.Sprintf("chain %s check failed", name))
		}
		for _, r := range rules {
			res := table.Check(r)
			Expect(res).NotTo(BeTrue(), fmt.Sprintf("rule %s check failed", r))
		}
	})

	It("vyosIptables_test parseIpTableRule", func() {
		var helper VyosIpTableHelper
		table := NewIpTables(FirewallTable)
		table.priorityOfLastRule = 100

		rule := NewIpTableRule("eth1.in")
		helper.parseIpTableRule(rule, table)
		Expect(rule.priority == 100).To(BeTrue(), fmt.Sprintf("get default priority failed: %d", rule.priority))

		rule = NewIpTableRule("for test")
		helper.parseIpTableRule(rule, table)
		Expect(rule.priority == 100).To(BeTrue(), fmt.Sprintf("get default priority failed: %d", rule.priority))

		rule = NewIpTableRule("eth1.in")
		rule.setComment("for test")
		helper.parseIpTableRule(rule, table)
		Expect(rule.priority == 100).To(BeTrue(), fmt.Sprintf("get default priority failed: %d", rule.priority))

		rule = NewIpTableRule("eth1.in")
		rule.comment = FirewallRule
		rule.ruleNumber = 1234
		rule.setComment(getComment(rule))
		helper.parseIpTableRule(rule, table)
		Expect(rule.priority == 1234).To(BeTrue(), fmt.Sprintf("get default priority failed: %d", rule.priority))
	})

	It("vyosIptables_test getNextRuleNumber", func() {
		var helper VyosIpTableHelper
		table := NewIpTables(FirewallTable)

		rule := NewIpTableRule("eth1.in")
		rule.ruleNumber = 1001
		res := helper.getNextRuleNumber(table, rule)
		Expect(res == 1001).To(BeTrue(), fmt.Sprintf("get rulenum failed: %d", res))

		rule = NewIpTableRule("eth1.in")
		res = helper.getNextRuleNumber(table, rule)
		Expect(res == 0).To(BeTrue(), fmt.Sprintf("get rulenum failed: %d", res))

		rule = NewIpTableRule("eth1.in")
		rule.SetComment(EipRuleComment)
		res = helper.getNextRuleNumber(table, rule)
		Expect(res == FORWARD_CHAIN_SERVICE_RULE_NUMBER_MIN).To(BeTrue(), fmt.Sprintf("get rulenum failed: %d", res))

		rule = NewIpTableRule("eth1.in")
		rule.SetComment(SystemTopRule)
		res = helper.getNextRuleNumber(table, rule)
		Expect(res == FORWARD_CHAIN_SYSTEM_RULE_RULE_NUMBER_MIN).To(BeTrue(), fmt.Sprintf("get rulenum failed: %d", res))

		rule = NewIpTableRule("eth1.local")
		rule.SetComment(EipRuleComment)
		res = helper.getNextRuleNumber(table, rule)
		Expect(res == LOCAL_CHAIN_SERVICE_RULE_NUMBER_MIN).To(BeTrue(), fmt.Sprintf("get rulenum failed: %d", res))

		rule = NewIpTableRule("eth1.local")
		rule.SetComment(SystemTopRule)
		res = helper.getNextRuleNumber(table, rule)
		Expect(res == LOCAL_CHAIN_SYSTEM_RULE_RULE_NUMBER_MIN).To(BeTrue(), fmt.Sprintf("get rulenum failed: %d", res))
	})

	It("vyosIptables_test getPriorityFromComment", func() {
		table := NewIpTables(FirewallTable)
		table.priorityOfLastRule = 100

		rule := NewIpTableRule("eth1.in")
		_, err := getPriorityFromComment(rule)
		Expect(err).NotTo(BeNil(), fmt.Sprintf("get priority failed: %v", err))

		rule = NewIpTableRule("for test")
		_, err = getPriorityFromComment(rule)
		Expect(err).NotTo(BeNil(), fmt.Sprintf("get priority failed: %v", err))

		rule = NewIpTableRule("eth1.in")
		rule.setComment("for test")
		_, err = getPriorityFromComment(rule)
		Expect(err).NotTo(BeNil(), fmt.Sprintf("get priority failed: %v", err))

		rule = NewIpTableRule("eth1.in")
		rule.comment = FirewallRule
		rule.ruleNumber = 1234
		rule.setComment(getComment(rule))
		priority, err := getPriorityFromComment(rule)
		Expect(err).To(BeNil(), fmt.Sprintf("get priority failed: %v", err))
		Expect(priority == 1234).To(BeTrue(), fmt.Sprintf("get priority failed: %d", priority))
	})

	It("vyosIptables_test add rule by customer", func() {
		InitNicFirewall(PrivateNicsForUT[0].Name, PrivateNicsForUT[0].Ip, false, "REJECT")

		cmds := []string{"iptables -I eth3.in -s 1.1.1.1/32 -j DROP"}
		cmds = append(cmds, "iptables -I eth3.in 3 -s 1.1.1.2/32 -j DROP")
		cmds = append(cmds, "iptables -A eth3.in -s 1.1.1.3/32 -j DROP")
		cmds = append(cmds, "iptables -I eth3.local -s 1.1.1.4/32 -j DROP")
		cmds = append(cmds, "iptables -I eth3.local 3 -s 1.1.1.5/32 -j DROP")
		cmds = append(cmds, "iptables -A eth3.local -s 1.1.1.6/32 -j DROP")
		b := Bash{
			Command: strings.Join(cmds, "\n"),
			Sudo:    true,
		}

		ret, _, _, err := b.RunWithReturn()
		Expect(err).To(BeNil(), fmt.Sprintf("add iptables[%s] failed: %v", cmds, err))
		Expect(ret == 0).To(BeTrue(), fmt.Sprintf("add iptables[%s] failed: ret = %d", cmds, ret))

		var rules []*IpTableRule
		localChain := GetRuleSetName(PrivateNicsForUT[0].Name, RULESET_LOCAL)
		fwdChain := GetRuleSetName(PrivateNicsForUT[0].Name, RULESET_IN)
		table := NewIpTables(FirewallTable)
		rule := NewIpTableRule(fwdChain)
		rule.SetSrcIp("1.1.1.1/32").SetAction("DROP")
		rules = append(rules, rule)
		rule = NewIpTableRule(fwdChain)
		rule.SetSrcIp("1.1.1.2/32").SetAction("DROP")
		rules = append(rules, rule)
		rule = NewIpTableRule(fwdChain)
		rule.SetSrcIp("1.1.1.3/32").SetAction("DROP")
		rules = append(rules, rule)
		rule = NewIpTableRule(localChain)
		rule.SetSrcIp("1.1.1.4/32").SetAction("DROP")
		rules = append(rules, rule)
		rule = NewIpTableRule(localChain)
		rule.SetSrcIp("1.1.1.5/32").SetAction("DROP")
		rules = append(rules, rule)
		rule = NewIpTableRule(localChain)
		rule.SetSrcIp("1.1.1.6/32").SetAction("DROP")
		rules = append(rules, rule)
		for _, r := range rules {
			res := table.Check(r)
			Expect(res).To(BeTrue(), fmt.Sprintf("rule [%s] not found", r))
		}

		/* add pf, eip, default rule, firewall to forward chain */
		var zsrules []*IpTableRule
		rule = NewIpTableRule(fwdChain)
		rule.SetComment(PortFordingRuleComment)
		rule.SetSrcIp("2.1.1.1/32").SetAction(IPTABLES_ACTION_RETURN)
		zsrules = append(zsrules, rule)
		rule = NewIpTableRule(fwdChain)
		rule.SetComment(EipRuleComment)
		rule.SetSrcIp("2.1.1.2/32").SetAction(IPTABLES_ACTION_RETURN)
		zsrules = append(zsrules, rule)
		rule = NewIpTableRule(fwdChain)
		rule.SetComment(SystemTopRule)
		rule.SetSrcIp("2.1.1.3/32").SetAction(IPTABLES_ACTION_RETURN)
		zsrules = append(zsrules, rule)
		rule = NewIpTableRule(fwdChain)
		rule.ruleNumber = 1002
		rule.SetComment(FirewallRule)
		rule.SetSrcIp("2.1.1.4/32").SetAction(IPTABLES_ACTION_RETURN)
		zsrules = append(zsrules, rule)

		rule = NewIpTableRule(localChain)
		rule.SetComment(SystemTopRule)
		rule.SetSrcIp("2.1.1.5/32").SetAction(IPTABLES_ACTION_RETURN)
		zsrules = append(zsrules, rule)
		rule = NewIpTableRule(localChain)
		rule.SetComment(IpsecRuleComment)
		rule.SetSrcIp("2.1.1.6/32").SetAction(IPTABLES_ACTION_RETURN)
		zsrules = append(zsrules, rule)
		rule = NewIpTableRule(localChain)
		rule.SetComment(LbRuleComment)
		rule.SetSrcIp("2.1.1.7/32").SetAction(IPTABLES_ACTION_RETURN)
		zsrules = append(zsrules, rule)

		table.AddIpTableRules(zsrules)
		table.Apply()

		for _, r := range rules {
			res := table.Check(r)
			Expect(res).To(BeTrue(), fmt.Sprintf("rule [%s] not found", r))
		}

		for _, r := range zsrules {
			res := table.Check(r)
			Expect(res).To(BeTrue(), fmt.Sprintf("zs rule [%s] not found", r))
		}

		DestroyNicFirewall(PrivateNicsForUT[0].Name)
	})

	It("destroying vyosIptables_test", func() {
		SetSkipVyosIptablesForUT(false)
	})
})
