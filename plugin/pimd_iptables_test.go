package plugin

import (
	"fmt"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("pimd_iptables_test", func() {
	var nicCmd *configureNicCmd

	It("[IPTABLES]pimd : test preparing", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"pimd_iptables_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
		nicCmd = &configureNicCmd{}
	})

	It("[IPTABLES]pimd : test add pimd and remove pimd", func() {
		pimdEnable = true
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		configureNic(nicCmd)

		nics := make(map[string]utils.Nic)
		for _, nic := range nicCmd.Nics {
			name, err := utils.GetNicNameByMac(nic.Mac)
			if err != nil {
				continue
			}
			checkRegisterAddNicCallback(name)
			nics[name] = utils.Nic{
				Name: nic.Name,
				Mac:  nic.Mac,
			}
		}
		log.Debugf("[IPTABLES]pimd : test add pimd ###########")
		addPimdFirewallByIptables(nics)
		checkAddPimdFirewallByIptables(nics)

		log.Debugf("[IPTABLES]pimd : test remove pimd ###########")
		removePimdFirewallByIptables(nics)
		checkRemovePimdFirewallByIptables(nics)

		pimdEnable = false
	})

	It("[IPTABLES]pimd : destroying", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkRegisterAddNicCallback(nic string) {
	table := utils.NewIpTables(utils.FirewallTable)

	rule := utils.NewIpTableRule(utils.GetRuleSetName(nic, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule.SetProto(utils.IPTABLES_PROTO_PIMD).SetInNic(nic)
	res := table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	rule = utils.NewIpTableRule(utils.GetRuleSetName(nic, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule.SetProto(utils.IPTABLES_PROTO_IGMP).SetInNic(nic)
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
}

func checkAddPimdFirewallByIptables(nics map[string]utils.Nic) {
	table := utils.NewIpTables(utils.FirewallTable)
	for _, nic := range nics {
		rules := table.Found(utils.GetRuleSetName(nic.Name, utils.RULESET_LOCAL), utils.SystemTopRule)
		for _, rule := range rules {
			if rule.GetProto() == utils.IPTABLES_PROTO_PIMD {
				Expect(rule.GetRuleNumber() < utils.LOCAL_CHAIN_SYSTEM_RULE_RULE_NUMBER_MAX).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
			}
			if rule.GetProto() == utils.IPTABLES_PROTO_IGMP {
				Expect(rule.GetRuleNumber() < utils.LOCAL_CHAIN_SYSTEM_RULE_RULE_NUMBER_MAX).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
			}
		}
		rules = table.Found(utils.GetRuleSetName(nic.Name, utils.RULESET_IN), utils.SystemTopRule)
		for _, rule := range rules {
			if rule.GetDstIp() == "224.0.0.0/4" {
				Expect(rule.GetRuleNumber() > utils.LOCAL_CHAIN_SYSTEM_RULE_RULE_NUMBER_MAX).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
			}
		}

		rule := utils.NewIpTableRule(utils.GetRuleSetName(nic.Name, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_PIMD)
		res := table.Check(rule)
		Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

		rule = utils.NewIpTableRule(utils.GetRuleSetName(nic.Name, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_IGMP)
		res = table.Check(rule)
		Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

		rule = utils.NewIpTableRule(utils.GetRuleSetName(nic.Name, utils.RULESET_IN))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetDstIp("224.0.0.0/4")
		rule.SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
		res = table.Check(rule)
		Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
	}
}

func checkRemovePimdFirewallByIptables(nics map[string]utils.Nic) {
	table := utils.NewIpTables(utils.FirewallTable)

	for _, nic := range nics {
		rule := utils.NewIpTableRule(utils.GetRuleSetName(nic.Name, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_PIMD)
		res := table.Check(rule)
		Expect(res).To(BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

		rule = utils.NewIpTableRule(utils.GetRuleSetName(nic.Name, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_IGMP)
		res = table.Check(rule)
		Expect(res).To(BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

		rule = utils.NewIpTableRule(utils.GetRuleSetName(nic.Name, utils.RULESET_IN))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetDstIp("224.0.0.0/4")
		rule.SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
		res = table.Check(rule)
		Expect(res).To(BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
	}
}
