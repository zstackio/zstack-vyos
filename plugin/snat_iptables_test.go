package plugin

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/zstackio/zstack-vyos/utils"
)

var _ = Describe("snat_iptables_test", func() {
	var sinfo1 snatInfo
	var sinfo2 snatInfo
	var rmCmd *removeSnatCmd
	var nicCmd *configureNicCmd

	It("[IPTABLES]snat : test preparing", func() {
		utils.InitLog(utils.VYOS_UT_LOG_FOLDER+"snat_iptables_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
		sinfo1 = snatInfo{
			PublicNicMac:  utils.PubNicForUT.Mac,
			PublicIp:      utils.PubNicForUT.Ip,
			PrivateNicMac: utils.PrivateNicsForUT[0].Mac,
			PrivateNicIp:  utils.PrivateNicsForUT[0].Ip,
			SnatNetmask:   utils.PrivateNicsForUT[0].Netmask,
			State:         true,
		}
		sinfo2 = snatInfo{
			PublicNicMac:  utils.PubNicForUT.Mac,
			PublicIp:      utils.PubNicForUT.Ip,
			PrivateNicMac: utils.PrivateNicsForUT[1].Mac,
			PrivateNicIp:  utils.PrivateNicsForUT[1].Ip,
			SnatNetmask:   utils.PrivateNicsForUT[1].Netmask,
			State:         true,
		}
		rmCmd = &removeSnatCmd{NatInfo: []snatInfo{sinfo1, sinfo2}}
		nicCmd = &configureNicCmd{}
	})

	It("[IPTABLES]snat : test set snat and remove snat", func() {
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[1])
		configureNic(nicCmd)
		cmd1 := &setSnatCmd{Snat: sinfo1}
		cmd2 := &setSnatCmd{Snat: sinfo2}
		setSnat(cmd1)
		checkSnatRuleSetIptables(cmd1)

		setSnat(cmd2)
		checkSnatRuleSetIptables(cmd2)

		removeSnat(rmCmd)
		checkSnatRuleDelIptables(rmCmd)
	})

	It("[IPTABLES]snat : test set snat state", func() {
		stateCmd := &setSnatStateCmd{Snats: []snatInfo{sinfo1, sinfo2}, Enable: true}
		setSnatState(stateCmd)
		checkSyncSnatByIptables(stateCmd.Snats, stateCmd.Enable)

		removeSnat(rmCmd)
		checkSnatRuleDelIptables(rmCmd)
	})

	It("[IPTABLES]snat : test sync snat", func() {
		syncCmd := &syncSnatCmd{Snats: []snatInfo{sinfo1, sinfo2}, Enable: true}
		syncSnat(syncCmd)
		checkSyncSnatByIptables(syncCmd.Snats, syncCmd.Enable)

		removeSnat(rmCmd)
		checkSnatRuleDelIptables(rmCmd)
	})

	It("[IPTABLES]snat : test sync non-public networksnat", func() {
		sinfo1.State = true
		sinfo2.State = false
		syncCmd := &syncSnatCmd{Snats: []snatInfo{sinfo1, sinfo2}, Enable: true}
		syncSnat(syncCmd)
		checkSyncSnatByIptables(syncCmd.Snats, syncCmd.Enable)

		sinfo2.State = true
		setState := &setSnatStateCmd{Snats: []snatInfo{sinfo2}, Enable: true}
		setSnatState(setState)
		checkSyncSnatByIptables(syncCmd.Snats, syncCmd.Enable)

		sinfo2.State = false
		setState1 := &setSnatStateCmd{Snats: []snatInfo{sinfo2}, Enable: false}
		setSnatState(setState1)
		checkSyncSnatByIptables(syncCmd.Snats, syncCmd.Enable)

		removeSnat(rmCmd)
		checkSnatRuleDelIptables(rmCmd)
	})

	It("[IPTABLES]snat : destroying", func() {
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[1])
		removeNic(nicCmd)
		for i, _ := range nicCmd.Nics {
			checkNicFirewallDeleteByIpTables(nicCmd.Nics[i])
		}

		utils.SetSkipVyosIptablesForUT(false)
	})
})

func checkSnatRuleSetIptables(cmd *setSnatCmd) {
	s := cmd.Snat
	outNic, err := utils.GetNicNameByMac(s.PublicNicMac)
	utils.PanicOnError(err)
	inNic, err := utils.GetNicNameByMac(s.PrivateNicMac)
	utils.PanicOnError(err)
	address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
	utils.PanicOnError(err)

	table := utils.NewIpTables(utils.NatTable)
	rule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
	rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.SNATComment)
	rule.SetDstIp("! 224.0.0.0/8").SetSrcIp(address).SetOutNic(outNic).SetSnatTargetIp(s.PublicIp)
	res := table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	rule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
	rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.SNATComment)
	rule.SetDstIp("! 224.0.0.0/8").SetSrcIp(address).SetSrcIpRange(fmt.Sprintf("! %s", s.PrivateNicIp)).
		SetOutNic(inNic).SetSnatTargetIp(s.PublicIp)
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
}
func checkSnatRuleDelIptables(cmd *removeSnatCmd) {
	table := utils.NewIpTables(utils.NatTable)
	for _, s := range cmd.NatInfo {
		publicNic, err := utils.GetNicNameByMac(s.PublicNicMac)
		utils.PanicOnError(err)
		priNic, err := utils.GetNicNameByMac(s.PrivateNicMac)
		utils.PanicOnError(err)
		address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
		utils.PanicOnError(err)

		rule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.SNATComment)
		rule.SetDstIp("! 224.0.0.0/8").SetSrcIp(address).SetOutNic(publicNic).SetSnatTargetIp(s.PublicIp)
		res := table.Check(rule)
		Expect(res).To(BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

		rule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.SNATComment)
		rule.SetDstIp("! 224.0.0.0/8").SetSrcIp(address).SetSrcIpRange(fmt.Sprintf("! %s", s.PrivateNicIp)).
			SetOutNic(priNic).SetSnatTargetIp(s.PublicIp)
		res = table.Check(rule)
		Expect(res).To(BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
	}
}

func checkSyncSnatByIptables(Snats []snatInfo, state bool) {
	table := utils.NewIpTables(utils.NatTable)
	for _, s := range Snats {
		outNic, err := utils.GetNicNameByMac(s.PublicNicMac)
		utils.PanicOnError(err)
		inNic, err := utils.GetNicNameByMac(s.PrivateNicMac)
		utils.PanicOnError(err)
		address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
		utils.PanicOnError(err)

		rule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.SNATComment)
		rule.SetDstIp("! 224.0.0.0/8").SetSrcIp(address).SetOutNic(outNic).SetSnatTargetIp(s.PublicIp)
		res := table.Check(rule)
		if s.State == true {
			Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] should exist", rule.String()))
		} else {
			Expect(res).To(BeFalse(), fmt.Sprintf("firewall rule [%s] should not exist", rule.String()))
		}

		rule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.SNATComment)
		rule.SetDstIp("! 224.0.0.0/8").SetSrcIp(address).SetSrcIpRange(fmt.Sprintf("! %s", s.PrivateNicIp)).
			SetOutNic(inNic).SetSnatTargetIp(s.PublicIp)
		res = table.Check(rule)
		if s.State == true {
			Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] should exist", rule.String()))
		} else {
			Expect(res).To(BeFalse(), fmt.Sprintf("firewall rule [%s] should not exist", rule.String()))
		}
	}
}
