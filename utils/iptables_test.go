package utils

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("iptables_test", func() {

	It("preparing iptables_test", func() {
		InitLog(GetVyosUtLogDir()+"iptables-test.log", false)
		SetSkipVyosIptablesForUT(true)
	})

	It("iptables_test filter table rule parse", func() {
		t := NewIpTables("filter")
		t.Chains = []*IpTableChain{&IpTableChain{Name: "FORWARD"}}

		r, err := t.parseIpTablesRule("-I FORWARD -j VYATTA_FW_IN_HOOK")
		Expect(err).NotTo(BeNil(), fmt.Sprintf("wrong iptables %s", err))

		r, err = t.parseIpTablesRule("-A INPUT -j VYATTA_FW_IN_HOOK")
		Expect(err).NotTo(BeNil(), fmt.Sprintf("wrong iptables rule: %s", err))

		str := "-A FORWARD -i eth0 -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD ! -i eth0 -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD -o eth0 -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD ! -o eth0 -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD -s 10.86.0.227/32 -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD ! -s 10.86.0.227/32 -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD -d 10.86.0.227/32 -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD ! -d 10.86.0.227/32 -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD -p tcp -m tcp --sport 7272 -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD ! -p tcp -m tcp --sport 7272 -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: rule: %+v, str: %s", *r, r.String()))

		str = "-A FORWARD -p udp -m udp --dport 7272 -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD ! -p udp -m udp --dport 7272 -m comment --comment \"test\" -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD -m set --match-set eip-group dst -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD -m set ! --match-set eip-group src -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD -m state --state NEW,RELATED,ESTABLISHED -j RETURN"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD -m state ! --state NEW,RELATED,ESTABLISHED -j REJECT --reject-with icmp-port-unreachable"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD -m set --match-set eip-group dst -j DNAT --to-destination 10.86.4.109"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD -m set --match-set eip-group src -j DNAT --to-destination 10.86.4.109:9090"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))

		str = "-A FORWARD -m set --match-set eip-group src -j SNAT --to-source 172.20.16.196"
		r, err = t.parseIpTablesRule(str)
		Expect(strings.TrimSpace(r.String()) == str).To(BeTrue(), fmt.Sprintf("new rule: %s", r.String()))
	})

	It("iptables_test filter table parse", func() {
		t := NewIpTables("filter")

		conent := `*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:VYATTA_FW_IN_HOOK - [0:0]
:VYATTA_FW_LOCAL_HOOK - [0:0]
:VYATTA_FW_OUT_HOOK - [0:0]
:VYATTA_POST_FW_FWD_HOOK - [0:0]
:VYATTA_POST_FW_IN_HOOK - [0:0]
:VYATTA_POST_FW_OUT_HOOK - [0:0]
:VYATTA_PRE_FW_FWD_HOOK - [0:0]
:VYATTA_PRE_FW_IN_HOOK - [0:0]
:VYATTA_PRE_FW_OUT_HOOK - [0:0]
:eth0.in - [0:0]
:eth0.local - [0:0]
:eth1.in - [0:0]
:eth1.local - [0:0]
-A INPUT -j VYATTA_PRE_FW_IN_HOOK
-A INPUT -j VYATTA_FW_LOCAL_HOOK
-A INPUT -j VYATTA_POST_FW_IN_HOOK
-A FORWARD -j VYATTA_PRE_FW_FWD_HOOK
-A FORWARD -j VYATTA_FW_IN_HOOK
-A FORWARD -j VYATTA_FW_OUT_HOOK
-A FORWARD -j VYATTA_POST_FW_FWD_HOOK
-A OUTPUT -j VYATTA_PRE_FW_OUT_HOOK
-A OUTPUT -j VYATTA_POST_FW_OUT_HOOK
-A VYATTA_FW_IN_HOOK -i eth1 -j eth1.in
-A VYATTA_FW_IN_HOOK -i eth0 -j eth0.in
-A VYATTA_FW_LOCAL_HOOK -i eth1 -j eth1.local
-A VYATTA_FW_LOCAL_HOOK -i eth0 -j eth0.local
-A eth0.in -s 192.168.4.0/24 -m comment --comment "eth0.in-1" -m state --state NEW,RELATED,ESTABLISHED -j RETURN
-A eth0.in -m comment --comment "eth0.in-4000" -m state --state RELATED,ESTABLISHED -j RETURN
-A eth0.in -p icmp -m comment --comment "eth0.in-4001" -j RETURN
-A eth0.in -m comment --comment "eth0.in-4002" -m state --state NEW,RELATED,ESTABLISHED -m set --match-set eip-group dst -j RETURN
-A eth0.in -d 10.86.0.227/32 -p tcp -m comment --comment "eth0.in-4003" -m state --state NEW -m tcp --dport 700:800 -j RETURN
-A eth0.in -m comment --comment "eth0.in-9999" -m state --state NEW -j RETURN
-A eth0.in -m comment --comment "eth0.in-10000 default-action reject" -j REJECT --reject-with icmp-port-unreachable
-A eth0.local -d 172.20.16.196/32 -m comment --comment "eth0.local-1" -m state --state RELATED,ESTABLISHED -j RETURN
-A eth0.local -d 172.20.16.196/32 -p icmp -m comment --comment "eth0.local-2" -j RETURN
-A eth0.local -d 172.20.16.196/32 -p tcp -m comment --comment "eth0.local-3" -m tcp --dport 22 -j RETURN
-A eth0.local -d 172.20.16.196/32 -p tcp -m comment --comment "eth0.local-4" -m tcp --dport 7272 -j RETURN
-A eth0.local -p udp -m comment --comment "eth0.local-5" -m set --match-set ipsec-group src -m udp --dport 500 -j RETURN
-A eth0.local -p udp -m comment --comment "eth0.local-6" -m set --match-set ipsec-group src -m udp --dport 4500 -j RETURN
-A eth0.local -p esp -m comment --comment "eth0.local-7" -m set --match-set ipsec-group src -j RETURN
-A eth0.local -p ah -m comment --comment "eth0.local-8" -m set --match-set ipsec-group src -j RETURN
-A eth0.local -s 192.168.4.0/24 -m comment --comment "eth0.local-9" -m state --state NEW,RELATED,ESTABLISHED -j RETURN
-A eth0.local -m comment --comment "eth0.local-10000 default-action reject" -j REJECT --reject-with icmp-port-unreachable
COMMIT
`
		err := t.parseIpTables(conent)
		Expect(err).To(BeNil(), fmt.Sprintf("parse iptables failed %s", err))

		chainName := []string{"eth0.in", "eth0.local", "eth1.in", "eth1.local"}
		for _, name := range chainName {
			found := t.CheckChain(name)
			Expect(found).To(BeTrue(), fmt.Sprintf("chain %s parse failed, chains %+v", name, t.Chains))
		}

		var rules []*IpTableRule
		r := NewIpTableRule(VYOS_FWD_ROOT_CHAIN).SetAction("eth1.in").SetInNic("eth1")
		rules = append(rules, r)

		r = NewIpTableRule("eth0.local").SetAction(IPTABLES_ACTION_REJECT).SetRejectType("icmp-port-unreachable")
		rules = append(rules, r)

		r = NewIpTableRule("eth0.in").SetAction(IPTABLES_ACTION_RETURN)
		r.SetDstIp("10.86.0.227/32").SetProto("tcp").SetDstPort("700:800")
		r.SetState([]string{IPTABLES_STATE_NEW})
		rules = append(rules, r)

		for _, rule := range rules {
			found := t.Check(rule)
			Expect(found).To(BeTrue(), fmt.Sprintf("rule %s parse failed", rule.String()))
		}
	})

	It("iptables_test AddIpTableRules", func() {
		t1 := NewIpTables(FirewallTable)
		log.Debugf("iptables AddIpTableRules #######")
		chainName := GetRuleSetName("eth0", RULESET_IN)
		t1.Flush(chainName)
		t1.AddChain(chainName)

		r1 := NewIpTableRule(chainName)
		r1.SetAction(IPTABLES_ACTION_RETURN).SetComment(PortFordingRuleComment)
		r1.SetDstIp("172.20.10.10/32").SetState([]string{IPTABLES_STATE_NEW, IPTABLES_STATE_RELATED, IPTABLES_STATE_ESTABLISHED})
		t1.AddIpTableRules([]*IpTableRule{r1})
		res := t1.Check(r1)
		Expect(res).To(BeTrue(), "iptable rule %s add to table failed", r1.String())

		err := t1.Apply()
		Expect(err).To(BeNil(), "iptable rule %s add failed, %+v", r1.String(), err)

		t1 = NewIpTables(FirewallTable)
		res = t1.Check(r1)
		Expect(res).To(BeTrue(), "iptable rule %s add in linux failed", r1.String())

		r2 := t1.Found(chainName, PortFordingRuleComment)
		Expect(len(r2) == 1).To(BeTrue(), "found rule failed: %d", len(r2))
		Expect(r2[0].IsRuleEqual(r1)).To(BeNil(), "found rule failed: %+v", r2[0])

		t1.AddIpTableRules([]*IpTableRule{r1})
		/* rule add twice, there should only 1 record in rules */
		r2 = t1.Found(chainName, PortFordingRuleComment)
		Expect(len(r2) == 1).To(BeTrue(), "found rule failed: %d", len(r2))

		err = t1.Apply()
		Expect(err).To(BeNil(), "iptable rule %s add failed, %+v", r1.String(), err)
		t1 = NewIpTables(FirewallTable)
		res = t1.Check(r1)
		Expect(res).To(BeTrue(), "iptable rule %s add in linux again failed", r1.String())

		/* add a rule before pf */
		r3 := NewIpTableRule(chainName)
		r3.SetAction(IPTABLES_ACTION_RETURN).SetComment(SystemTopRule)
		r3.SetDstIp("172.20.10.10/32").SetTcpFlags([]string{"SYN"})
		t1.addIpTableRule(r3)

		/* add a rule after pf */
		r4 := NewIpTableRule(chainName)
		r4.SetAction(IPTABLES_ACTION_RETURN).SetComment(EipRuleComment)
		r4.SetDstIp("172.20.10.100/32").SetProto(IPTABLES_PROTO_ESP)
		t1.addIpTableRule(r4)

		systemSeq := 0
		pfSeq := 0
		eipSeq := 0
		for i, r := range t1.Rules {
			if strings.Contains(r.comment, SystemTopRule) {
				systemSeq = i + 1
			} else if strings.Contains(r.comment, PortFordingRuleComment) {
				pfSeq = i + 1
			} else if strings.Contains(r.comment, EipRuleComment) {
				eipSeq = i + 1
			}
		}
		Expect(systemSeq != 0).To(BeTrue(), "system rule not added")
		Expect(pfSeq != 0).To(BeTrue(), "pf rule not added")
		Expect(eipSeq != 0).To(BeTrue(), "eip rule not added")
		Expect(systemSeq < pfSeq).To(BeTrue(), "system rule is before pf rule")
		Expect(pfSeq < eipSeq).To(BeTrue(), "pf rule is before eip rule")
		t1.Apply()

		/* check result in linux */
		t1 = NewIpTables(FirewallTable)
		systemSeq = 0
		pfSeq = 0
		eipSeq = 0
		for i, r := range t1.Rules {
			if strings.Contains(r.comment, SystemTopRule) {
				systemSeq = i + 1
			} else if strings.Contains(r.comment, PortFordingRuleComment) {
				pfSeq = i + 1
			} else if strings.Contains(r.comment, EipRuleComment) {
				eipSeq = i + 1
			}
		}
		Expect(systemSeq != 0).To(BeTrue(), "system rule not added")
		Expect(pfSeq != 0).To(BeTrue(), "pf rule not added")
		Expect(eipSeq != 0).To(BeTrue(), "eip rule not added")
		Expect(systemSeq < pfSeq).To(BeTrue(), "system rule is before pf rule")
		Expect(pfSeq < eipSeq).To(BeTrue(), "pf rule is before eip rule")

		t1.RemoveIpTableRule([]*IpTableRule{r1, r1, r3, r4})
		res = t1.Check(r1)
		Expect(res).NotTo(BeTrue(), "iptable rule %+v delete in table failed", r1)

		err = t1.Apply()
		Expect(err).To(BeNil(), "iptable rule %+v del failed, %+v", r1, err)

		t1 = NewIpTables(FirewallTable)
		res = t1.Check(r1)
		Expect(res).NotTo(BeTrue(), "iptable rule %+v delete in linux failed", r1)

		t1.removeChainRules(chainName)
		err = t1.Apply()
		Expect(err).To(BeNil(), "iptable remove chain: %s", chainName, err)
		t1 = NewIpTables(FirewallTable)
		res = t1.CheckChain(chainName)
		Expect(res).NotTo(BeTrue(), "iptable remove chain: %s in linux failed", chainName)
	})

	It("iptables_test RemoveIpTableRuleByComments", func() {
		InitNicFirewall(PrivateNicsForUT[0].Name, PrivateNicsForUT[0].Ip, false, "REJECT")

		t1 := NewIpTables(FirewallTable)

		var rules []*IpTableRule
		rule := NewIpTableRule(GetRuleSetName(PrivateNicsForUT[0].Name, RULESET_LOCAL))
		rule.SetAction(IPTABLES_ACTION_RETURN).SetDstIp("192.168.1.1/32")
		rule.SetComment(EipRuleComment)
		rules = append(rules, rule)

		rule = NewIpTableRule(GetRuleSetName(PrivateNicsForUT[0].Name, RULESET_LOCAL))
		rule.SetAction(IPTABLES_ACTION_RETURN).SetDstIp("192.168.1.2/32")
		rule.SetComment(EipRuleComment)
		rules = append(rules, rule)

		rule = NewIpTableRule(GetRuleSetName(PrivateNicsForUT[0].Name, RULESET_LOCAL))
		rule.SetAction(IPTABLES_ACTION_RETURN).SetDstIp("192.168.1.3/32")
		rule.SetComment(EipRuleComment)
		rules = append(rules, rule)

		t1.AddIpTableRules(rules)
		t1.Apply()

		t1 = NewIpTables(FirewallTable)
		for _, r := range rules {
			res := t1.Check(r)
			Expect(res).To(BeTrue(), fmt.Sprintf("rule %s check failed", r))
		}

		t1.RemoveIpTableRuleByComments(EipRuleComment)
		t1.Apply()
		t1 = NewIpTables(FirewallTable)
		for _, r := range rules {
			res := t1.Check(r)
			Expect(res).To(BeFalse(), fmt.Sprintf("rule %s check failed", r))
		}

		DestroyNicFirewall(PrivateNicsForUT[0].Name)
	})

	It("iptables test move tmp filepath from /tmp to /home/vyos/zvr", func() {
		InitNicFirewall(PrivateNicsForUT[0].Name, PrivateNicsForUT[0].Ip, false, "DROP")
		t1 := NewIpTables(FirewallTable)

		var rules []*IpTableRule
		rule := NewIpTableRule(GetRuleSetName(PrivateNicsForUT[0].Name, RULESET_LOCAL))
		rule.SetAction(IPTABLES_ACTION_RETURN).SetDstIp("172.16.100.1/32")
		rule.SetComment(EipRuleComment)
		rules = append(rules, rule)

		rule = NewIpTableRule(GetRuleSetName(PrivateNicsForUT[0].Name, RULESET_LOCAL))
		rule.SetAction(IPTABLES_ACTION_RETURN).SetDstIp("172.16.200.1/32")
		rule.SetComment(EipRuleComment)
		rules = append(rules, rule)

		t1.AddIpTableRules(rules)
		err := t1.Apply()
		Expect(err).To(BeNil(), fmt.Sprintf("func Apply() check fialed"))
		t1 = NewIpTables(FirewallTable)
		for _, r := range rules {
			res := t1.Check(r)
			Expect(res).To(BeTrue(), fmt.Sprintf("rule %s check failed", r))
		}
		DestroyNicFirewall(PrivateNicsForUT[0].Name)
	})

	It("destroying iptables_test", func() {
		SetSkipVyosIptablesForUT(false)
	})
})
