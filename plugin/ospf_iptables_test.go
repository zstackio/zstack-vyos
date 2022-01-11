package plugin

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/zstackio/zstack-vyos/utils"
)

var _ = Describe("ospf_iptables_test", func() {
	var nicCmd *configureNicCmd

	It("[IPTABLES]ospf : test preparing", func() {
		utils.InitLog(utils.VYOS_UT_LOG_FOLDER+"ospf_iptables_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
		nicCmd = &configureNicCmd{}
	})

	It("[IPTABLES]ospf : test sync ospf", func() {
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		configureNic(nicCmd)

		info1 := networkInfo{
			NicMac:  utils.PubNicForUT.Mac,
			Network: utils.PubNicForUT.Ip,
			AreaId:  "0.0.0.2",
		}
		info2 := networkInfo{
			NicMac:  utils.PrivateNicsForUT[0].Mac,
			Network: utils.PrivateNicsForUT[0].Ip,
			AreaId:  "0.0.0.3",
		}
		NetworkInfos := []networkInfo{info1, info2}
		syncOspfRulesByIptables(NetworkInfos)
		checkSyncOspfRulesByIptables(NetworkInfos)
	})

	It("[IPTABLES]ospf : destroying", func() {
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		removeNic(nicCmd)
		for i, _ := range nicCmd.Nics {
			checkNicFirewallDeleteByIpTables(nicCmd.Nics[i])
		}
		utils.SetSkipVyosIptablesForUT(false)
	})
})

func checkSyncOspfRulesByIptables(NetworkInfos []networkInfo) {
	table := utils.NewIpTables(utils.FirewallTable)
	natTable := utils.NewIpTables(utils.NatTable)

	for _, info := range NetworkInfos {
		nicname, err := utils.GetNicNameByMac(info.NicMac)
		utils.PanicOnError(err)
		rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_OSPF)
		res := table.Check(rule)
		Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

		natRule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
		natRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		natRule.SetProto(utils.IPTABLES_PROTO_OSPF).SetOutNic(nicname)
		res = natTable.Check(natRule)
		Expect(res).To(BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", natRule.String()))
	}
}
