package plugin

import (
	"fmt"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("eip_iptables_test", func() {

	It("[IPTABLES]EIP : prepare", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"eip_iptables_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
		configureAllNicsForUT()
		cleanPluginMaps()
		eipMap = make(map[string]eipInfo, EipInfoMaxSize)
	})

	It("[IPTABLES]EIP : test create sync remove eip", func() {
		ipInPubL3, _ := utils.GetFreePubL3Ip()
		eip1 := eipInfo{VipIp: ipInPubL3, PublicMac: utils.PubNicForUT.Mac,
			GuestIp: "192.168.1.200", PrivateMac: utils.PrivateNicsForUT[0].Mac,
			SnatInboundTraffic: false}
		cmd1 := setEipCmd{Eip: eip1}
		log.Debugf("TestCreateEip createEip eip1: %+v", eip1)
		createEip(&cmd1)
		checkSyncEipByIptables(eip1)

		// eip1, and eip2 share same guestIp
		ipInPubL3_2, _ := utils.GetFreePubL3Ip()
		eip2 := eipInfo{VipIp: ipInPubL3_2, PublicMac: utils.PubNicForUT.Mac,
			GuestIp: "192.168.1.200", PrivateMac: utils.PrivateNicsForUT[0].Mac,
			SnatInboundTraffic: false}
		cmd2 := setEipCmd{Eip: eip2}
		log.Debugf("TestCreateEip createEip eip2: %+v", eip2)
		createEip(&cmd2)
		checkSyncEipByIptables(eip2)

		scmd := &syncEipCmd{Eips: []eipInfo{eip1, eip2}}
		log.Debugf("TestCreateEip syncEip eip1: %+v", scmd)
		syncEip(scmd)
		checkSyncEipByIptables(eip1)
		checkSyncEipByIptables(eip2)

		rcmd1 := &removeEipCmd{Eip: eip1}
		log.Debugf("TestCreateEip removeEip eip1: %+v", eip1)
		removeEip(rcmd1)
		checkRemoveEipByIptables(eip1)

		rcmd2 := &removeEipCmd{Eip: eip2}
		log.Debugf("TestCreateEip removeEip eip2: %+v", eip2)
		removeEip(rcmd2)
		checkRemoveEipByIptables(eip2)

		utils.ReleasePubL3Ip(ipInPubL3)
		utils.ReleasePubL3Ip(ipInPubL3_2)
	})

	It("[IPTABLES]EIP : test ipset add delete", func() {
		ipInPubL3, _ := utils.GetFreePubL3Ip()
		eip1 := eipInfo{VipIp: ipInPubL3, PublicMac: utils.PubNicForUT.Mac,
			GuestIp: "192.168.1.100", PrivateMac: utils.PrivateNicsForUT[0].Mac,
			SnatInboundTraffic: false,
		}
		cmd1 := setEipCmd{Eip: eip1}
		rcmd1 := &removeEipCmd{Eip: eip1}

		ipInPubL3_2, _ := utils.GetFreePubL3Ip()
		eip2 := eipInfo{VipIp: ipInPubL3_2, PublicMac: utils.PubNicForUT.Mac,
			GuestIp: "192.168.1.200", PrivateMac: utils.PrivateNicsForUT[0].Mac,
			SnatInboundTraffic: false,
		}
		cmd2 := setEipCmd{Eip: eip2}
		rcmd2 := &removeEipCmd{Eip: eip2}

		log.Debugf("#### test ipset add ####")
		createEip(&cmd1)
		checkEipIpsetRule([]eipInfo{eip1}, true)
		createEip(&cmd2)
		checkEipIpsetRule([]eipInfo{eip1, eip2}, true)

		log.Debugf("#### test ipset del ####")
		removeEip(rcmd1)
		checkEipIpsetRule([]eipInfo{eip2}, true)
		removeEip(rcmd2)
		checkEipIpsetRule([]eipInfo{eip1, eip2}, false)

		utils.ReleasePubL3Ip(ipInPubL3)
		utils.ReleasePubL3Ip(ipInPubL3_2)
	})

	It("[IPTABLES]EIP : destroying env", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkEipIpsetRule(eipList []eipInfo, flag bool) {
	for _, eip := range eipList {
		bash := utils.Bash{
			Command: fmt.Sprintf("ipset test %s %s", EIP_IPSET_NAME, eip.GuestIp),
			Sudo:    true,
		}
		_, _, _, err := bash.RunWithReturn()
		if flag == true {
			gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("Ipset add rule [%s] check failed", eip.GuestIp))
		} else {
			gomega.Expect(err).NotTo(gomega.BeNil(), fmt.Sprintf("Ipset del rule [%s] check failed", eip.GuestIp))
		}
	}
}

func checkSyncEipByIptables(eip eipInfo) {

	filterTable := utils.NewIpTables(utils.FirewallTable)
	natTable := utils.NewIpTables(utils.NatTable)

	pubNic, _ := utils.GetNicNameByMac(eip.PublicMac)

	/* check nat rule */
	natRule := utils.NewIpTableRule(utils.RULESET_DNAT.String())
	natRule.SetAction(utils.IPTABLES_ACTION_DNAT).SetComment(utils.EipRuleComment)
	natRule.SetDstIp(eip.VipIp + "/32").SetDnatTargetIp(eip.GuestIp)
	res := natTable.Check(natRule)
	gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("nat rule [%s] check failed", natRule.String()))

	natRule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
	natRule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.EipRuleComment)
	natRule.SetOutNic(pubNic).SetSrcIp(eip.GuestIp + "/32").SetSnatTargetIp(eip.VipIp)
	res = natTable.Check(natRule)
	gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("nat rule [%s] check failed", natRule.String()))

	privNic, _ := utils.GetNicNameByMac(eip.PrivateMac)

	//qos not test
	if eip.SnatInboundTraffic {
		gwip, err := utils.GetIpByNicName(privNic)
		utils.PanicOnError(err)
		natRule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
		natRule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.EipRuleComment)
		natRule.SetOutNic(privNic).SetDstIp(eip.GuestIp + "/32").SetSnatTargetIp(gwip)
		res = natTable.Check(natRule)
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("nat rule [%s] check failed", natRule.String()))
	}

	/* check firewall rule */
	filterRule := utils.NewIpTableRule(utils.GetRuleSetName(pubNic, utils.RULESET_IN))
	filterRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.EipRuleComment)
	filterRule.SetDstIpset(EIP_IPSET_NAME).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
	res = filterTable.Check(filterRule)
	gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))

	filterRule = utils.NewIpTableRule(utils.GetRuleSetName(privNic, utils.RULESET_IN))
	filterRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.EipRuleComment)
	filterRule.SetSrcIpset(EIP_IPSET_NAME).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
	res = filterTable.Check(filterRule)
	gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))
}

func checkRemoveEipByIptables(eip eipInfo) {

	filterTable := utils.NewIpTables(utils.FirewallTable)
	natTable := utils.NewIpTables(utils.NatTable)

	pubNic, _ := utils.GetNicNameByMac(eip.PublicMac)

	/* check nat rule */
	natRule := utils.NewIpTableRule(utils.RULESET_DNAT.String())
	natRule.SetAction(utils.IPTABLES_ACTION_DNAT).SetComment(utils.EipRuleComment)
	natRule.SetDstIp(eip.VipIp + "/32").SetDnatTargetIp(eip.GuestIp)
	res := natTable.Check(natRule)
	gomega.Expect(res).To(gomega.BeFalse(), fmt.Sprintf("nat rule [%s] check failed", natRule.String()))

	natRule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
	natRule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.EipRuleComment)
	natRule.SetOutNic(pubNic).SetSrcIp(eip.GuestIp + "/32").SetSnatTargetIp(eip.VipIp)
	res = natTable.Check(natRule)
	gomega.Expect(res).To(gomega.BeFalse(), fmt.Sprintf("nat rule [%s] check failed", natRule.String()))

	privNic, _ := utils.GetNicNameByMac(eip.PrivateMac)

	//not cover test
	if eip.SnatInboundTraffic {
		gwip, err := utils.GetIpByNicName(privNic)
		utils.PanicOnError(err)
		natRule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
		natRule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.EipRuleComment)
		natRule.SetOutNic(privNic).SetDstIp(eip.GuestIp + "/32").SetSnatTargetIp(gwip)
		res = natTable.Check(natRule)
		gomega.Expect(res).To(gomega.BeFalse(), fmt.Sprintf("nat rule [%s] check failed", natRule.String()))
	}

	if eipIpset == nil {
		/* check firewall rule */
		filterRule := utils.NewIpTableRule(utils.GetRuleSetName(pubNic, utils.RULESET_IN))
		filterRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.EipRuleComment)
		filterRule.SetDstIpset(EIP_IPSET_NAME).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
		res = filterTable.Check(filterRule)
		gomega.Expect(res).NotTo(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))

		filterRule = utils.NewIpTableRule(utils.GetRuleSetName(privNic, utils.RULESET_IN))
		filterRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.EipRuleComment)
		filterRule.SetSrcIpset(EIP_IPSET_NAME).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
		res = filterTable.Check(filterRule)
		gomega.Expect(res).NotTo(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))
	}
}
