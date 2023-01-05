package plugin

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	server "github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
	"strings"
)

var _ = Describe("configure_nic_iptables_test", func() {
	var cmd *configureNicCmd

	It("configure_nic_iptables_test prepare", func() {
		utils.InitLog(utils.VYOS_UT_LOG_FOLDER+"configure_nic_iptables_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
		cmd = &configureNicCmd{}
	})

	It("configure_nic_iptables_test TestConfigureNic", func() {
		cmd.Nics = append(cmd.Nics, utils.PubNicForUT)
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.AdditionalPubNicsForUT[0])
		configureNic(cmd)

		log.Debugf("############### TestConfigureNic check FORWARD chain rules seq ###############")
		checkFORWARDChainRuleSequence()

		log.Debugf("############### TestConfigureNic ###############")
		checkNicFirewallIpTables(utils.PubNicForUT, utils.IPTABLES_ACTION_REJECT)
		checkNicFirewallIpTables(utils.PrivateNicsForUT[0], utils.IPTABLES_ACTION_REJECT)
		checkNicFirewallIpTables(utils.AdditionalPubNicsForUT[0], utils.IPTABLES_ACTION_REJECT)

		/* add lb listener: then add a private nic, lb firewall will be copy to this nic local chain */
		vip := utils.GetRandomIpForSubnet(utils.PrivateNicsForUT[0].Ip)
		realIp := utils.GetRandomIpForSubnet(utils.PrivateNicsForUT[0].Ip)
		vip1 := vipInfo{Ip: vip, Netmask: utils.PrivateNicsForUT[0].Netmask, Gateway: utils.PrivateNicsForUT[0].Gateway,
			OwnerEthernetMac: utils.PrivateNicsForUT[0].Mac}
		vipCmd := &setVipCmd{SyncVip: false, Vips: []vipInfo{vip1}, NicIps: []nicIpInfo{}}
		setVip(vipCmd)

		lb := lbInfo{}
		lb.LbUuid = "f2c7b2ff2f834e1ea20363f49122a3b4"
		lb.ListenerUuid = "23fb656e4f324e74a4889582104fcbf0"
		lb.InstancePort = 433
		lb.LoadBalancerPort = 433
		lb.Vip = vip
		lb.NicIps = append(lb.NicIps, realIp)
		lb.Mode = "http"
		lb.PublicNic = utils.PrivateNicsForUT[0].Mac
		lb.Parameters = append(lb.Parameters,
			"balancerWeight::192.168.100.10::100",
			"connectionIdleTimeout::60",
			"Nbprocess::1",
			"balancerAlgorithm::roundrobin",
			"healthCheckTimeout::2",
			"healthCheckTarget::tcp:default",
			"maxConnection::2000000",
			"httpMode::http-server-close",
			"accessControlStatus::enable",
			"healthyThreshold::2",
			"healthCheckInterval::5",
			"unhealthyThreshold::2")
		setLb(lb)

		/* same nic can not be added twice */
		log.Debugf("############### TestConfigureNic add new nic ###############")
		cmd = &configureNicCmd{}
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[1])
		configureNic(cmd)
		checkNicFirewallIpTables(utils.PubNicForUT, utils.IPTABLES_ACTION_REJECT)
		checkNicFirewallIpTables(utils.PrivateNicsForUT[0], utils.IPTABLES_ACTION_REJECT)
		checkNicFirewallIpTables(utils.PrivateNicsForUT[1], utils.IPTABLES_ACTION_REJECT)
		checkNicFirewallIpTables(utils.AdditionalPubNicsForUT[0], utils.IPTABLES_ACTION_REJECT)
		checkPrivateNicLb(utils.PrivateNicsForUT[1], lb)

		delLb(lb)
	})

	It("configure_nic_iptables_test TestConfigureNicFirewallDefaultAction", func() {
		log.Debugf("############### TestConfigureNicFirewallDefaultAction ###############")
		cmd.Nics = []utils.NicInfo{}
		cmd.Nics = append(cmd.Nics, utils.PubNicForUT)
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.AdditionalPubNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[1])
		for i, _ := range cmd.Nics {
			cmd.Nics[i].FirewallDefaultAction = "accept"
		}
		log.Debugf("############### TestConfigureNicFirewallDefaultAction accept ###############")
		configureNicDefaultAction(cmd)
		checkNicFirewallIpTables(utils.PubNicForUT, utils.IPTABLES_ACTION_RETURN)
		checkNicFirewallIpTables(utils.PrivateNicsForUT[0], utils.IPTABLES_ACTION_RETURN)
		checkNicFirewallIpTables(utils.PrivateNicsForUT[1], utils.IPTABLES_ACTION_RETURN)
		checkNicFirewallIpTables(utils.AdditionalPubNicsForUT[0], utils.IPTABLES_ACTION_RETURN)
	})

	It("configure_nic_iptables_test TestChangeDefaultNic", func() {
		log.Debugf("############### TestChangeDefaultNic ###############")

		sinfo1 = snatInfo{
			PublicNicMac:  utils.AdditionalPubNicsForUT[0].Mac,
			PublicIp:      utils.AdditionalPubNicsForUT[0].Ip,
			PrivateNicMac: utils.PrivateNicsForUT[0].Mac,
			PrivateNicIp:  utils.PrivateNicsForUT[0].Ip,
			SnatNetmask:   utils.PrivateNicsForUT[0].Netmask,
		}

		sinfo2 = snatInfo{
			PublicNicMac:  utils.AdditionalPubNicsForUT[0].Mac,
			PublicIp:      utils.AdditionalPubNicsForUT[0].Ip,
			PrivateNicMac: utils.PrivateNicsForUT[1].Mac,
			PrivateNicIp:  utils.PrivateNicsForUT[1].Ip,
			SnatNetmask:   utils.PrivateNicsForUT[1].Netmask,
		}

		ccmd := &ChangeDefaultNicCmd{}
		ccmd.NewNic = utils.AdditionalPubNicsForUT[0]
		ccmd.Snats = []snatInfo{sinfo1, sinfo2}
		log.Debugf("############### TestChangeDefaultNic change default nic ###############")
		changeDefaultNic(ccmd)
		checkSnatRuleSetByIptables(sinfo1)
		checkSnatRuleSetByIptables(sinfo2)

		sinfo1 = snatInfo{
			PublicNicMac:  utils.PubNicForUT.Mac,
			PublicIp:      utils.PubNicForUT.Ip,
			PrivateNicMac: utils.PrivateNicsForUT[0].Mac,
			PrivateNicIp:  utils.PrivateNicsForUT[0].Ip,
			SnatNetmask:   utils.PrivateNicsForUT[0].Netmask,
		}

		sinfo2 = snatInfo{
			PublicNicMac:  utils.PubNicForUT.Mac,
			PublicIp:      utils.PubNicForUT.Ip,
			PrivateNicMac: utils.PrivateNicsForUT[1].Mac,
			PrivateNicIp:  utils.PrivateNicsForUT[1].Ip,
			SnatNetmask:   utils.PrivateNicsForUT[1].Netmask,
		}
		ccmd.NewNic = utils.PubNicForUT
		ccmd.Snats = []snatInfo{sinfo1, sinfo2}
		log.Debugf("############### TestChangeDefaultNic change default nic again ###############")
		changeDefaultNic(ccmd)
		checkSnatRuleSetByIptables(sinfo1)
		checkSnatRuleSetByIptables(sinfo1)

		rcmd := removeSnatCmd{NatInfo: []snatInfo{sinfo2, sinfo1}}
		removeSnat(&rcmd)
	})

	It("configure_nic_iptables_test TestAddSecondaryIpFirewall", func() {
		log.Debugf("############### TestAddSecondaryIpFirewall ###############")

		tree := server.NewParserFromShowConfiguration().Tree
		ipPubL3, _ := utils.GetFreePubL3Ip()
		addSecondaryIpFirewall(utils.PubNicForUT.Name, ipPubL3, tree)

		checkSecondaryIpFirewallByIptables(utils.PubNicForUT, ipPubL3+"/32")

		utils.ReleasePubL3Ip(ipPubL3)
	})

	It("configure_nic_iptables_test destroying ", func() {
		cmd.Nics = append(cmd.Nics, utils.PubNicForUT)
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.AdditionalPubNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[1])

		removeNic(cmd)
		for i, _ := range cmd.Nics {
			checkNicFirewallDeleteByIpTables(cmd.Nics[i])
		}
		utils.SetSkipVyosIptablesForUT(false)
	})
})

func checkFORWARDChainRuleSequence() {
	tables := utils.NewIpTables("filter")
	chains := tables.GetChain("FORWARD")
	Expect(chains != nil).To(BeTrue(), fmt.Sprintf("FORWARD chain not exsiting"))

	bash := utils.Bash{Command: fmt.Sprintf("sudo iptables -t filter -nL FORWARD|awk  '{print $1}'|sed -n '3,6p'")}
	_, stdout, _, err := bash.RunWithReturn()
	Expect(err).To(BeNil(), fmt.Sprintf("bash to get FORWARD failed, error %v", err))
	var chainRules = `VYATTA_PRE_FW_FWD_HOOKVYATTA_FW_IN_HOOKVYATTA_FW_OUT_HOOKVYATTA_POST_FW_FWD_HOOK`

	Expect(strings.Replace(stdout, "\n", "", -1) == chainRules).To(BeTrue(), fmt.Sprintf("check FORWARD failed, correct rules %s, now rules %s", chainRules, stdout))

}

func checkNicFirewallIpTables(nic utils.NicInfo, defaultAction string) {
	table := utils.NewIpTables(utils.FirewallTable)
	nicname, _ := utils.GetNicNameByMac(nic.Mac)
	localChain := utils.GetRuleSetName(nicname, utils.RULESET_LOCAL)
	forwardChain := utils.GetRuleSetName(nicname, utils.RULESET_IN)
	outChain := utils.GetRuleSetName(nicname, utils.RULESET_OUT)

	rule := utils.NewIpTableRule(utils.VYOS_INPUT_ROOT_CHAIN)
	rule.SetAction(localChain).SetInNic(nicname)
	res := table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	rule = utils.NewIpTableRule(utils.VYOS_FWD_ROOT_CHAIN)
	rule.SetAction(forwardChain).SetInNic(nicname)
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	rule = utils.NewIpTableRule(utils.VYOS_FWD_OUT_ROOT_CHAIN)
	rule.SetAction(outChain).SetOutNic(nicname)
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	/* add Rules for FORWARD chain */
	rule = utils.NewIpTableRule(forwardChain)
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule.SetState([]string{utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	/*
	   rule = utils.NewIpTableRule(forwardChain)
	   rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	   rule.SetProto(utils.IPTABLES_PROTO_ICMP)
	   res = table.Check(rule)
	   Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))*/

	rule = utils.NewDefaultIpTableRule(forwardChain, utils.IPTABLES_RULENUMBER_9999)
	rule.SetAction(utils.IPTABLES_ACTION_RETURN)
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	rule = utils.NewDefaultIpTableRule(forwardChain, utils.IPTABLES_RULENUMBER_MAX)
	rule.SetAction(defaultAction)
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	rule = utils.NewIpTableRule(localChain)
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule.SetDstIp(nic.Ip + "/32").SetState([]string{utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	rule = utils.NewIpTableRule(localChain)
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule.SetDstIp(nic.Ip + "/32").SetProto(utils.IPTABLES_PROTO_ICMP)
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	if utils.IsMgtNic(nic.Name) {
		rule = utils.NewIpTableRule(localChain)
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetDstIp(nic.Ip + "/32").SetProto(utils.IPTABLES_PROTO_TCP).SetDstPort("22")
		res = table.Check(rule)
		Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

		rule = utils.NewIpTableRule(localChain)
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetDstIp(nic.Ip + "/32").SetProto(utils.IPTABLES_PROTO_TCP).SetDstPort("7272")
		res = table.Check(rule)
		Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
	} else {
		rule = utils.NewIpTableRule(localChain)
		rule.SetAction(utils.IPTABLES_ACTION_REJECT).SetRejectType(utils.REJECT_TYPE_ICMP_UNREACHABLE)
		rule.SetComment(utils.SystemTopRule).SetDstIp(nic.Ip + "/32").SetProto(utils.IPTABLES_PROTO_TCP).SetDstPort("22")
		res = table.Check(rule)
		Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
	}

	rule = utils.NewDefaultIpTableRule(localChain, utils.IPTABLES_RULENUMBER_MAX)
	rule.SetAction(defaultAction)
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
}

func checkSnatRuleSetByIptables(s snatInfo) {
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
	rule.SetDstIp("! 224.0.0.0/8").SetSrcIp(address).SetSrcIpRange(fmt.Sprintf("! %s-%s", s.PrivateGatewayIp, s.PrivateGatewayIp)).
		SetOutNic(inNic).SetSnatTargetIp(s.PublicIp)
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
}

func checkSecondaryIpFirewallByIptables(nic utils.NicInfo, ip string) {
	table := utils.NewIpTables(utils.FirewallTable)
	nicname, _ := utils.GetNicNameByMac(nic.Mac)
	rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
	rule.SetComment(utils.SystemTopRule).SetAction(utils.IPTABLES_ACTION_ACCEPT)
	rule.SetDstIp(ip).SetState([]string{utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
	res := table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	rule1 := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
	rule1.SetComment(utils.SystemTopRule).SetAction(utils.IPTABLES_ACTION_ACCEPT)
	rule1.SetDstIp(ip).SetProto(utils.IPTABLES_PROTO_ICMP)
	res = table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
}

func checkNicFirewallDeleteByIpTables(nic utils.NicInfo) {
	table := utils.NewIpTables(utils.FirewallTable)
	nicname, _ := utils.GetNicNameByMac(nic.Mac)
	localChain := utils.GetRuleSetName(nicname, utils.RULESET_LOCAL)
	forwardChain := utils.GetRuleSetName(nicname, utils.RULESET_IN)
	outChain := utils.GetRuleSetName(nicname, utils.RULESET_OUT)

	rule := utils.NewIpTableRule(utils.VYOS_INPUT_ROOT_CHAIN)
	rule.SetAction(localChain).SetInNic(nicname)
	res := table.Check(rule)
	Expect(res).NotTo(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	rule = utils.NewIpTableRule(utils.VYOS_FWD_ROOT_CHAIN)
	rule.SetAction(forwardChain).SetInNic(nicname)
	res = table.Check(rule)
	Expect(res).NotTo(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	rule = utils.NewIpTableRule(utils.VYOS_FWD_OUT_ROOT_CHAIN)
	rule.SetAction(outChain).SetOutNic(nicname)
	res = table.Check(rule)
	Expect(res).NotTo(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
}

func checkPrivateNicLb(nic utils.NicInfo, lb lbInfo) {
	nicname, _ := utils.GetNicNameByMac(nic.Mac)

	table := utils.NewIpTables(utils.FirewallTable)
	rules := table.Found(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL), utils.LbRuleComment)
	Expect(len(rules) >= 1).To(BeTrue(), fmt.Sprintf("found lb rule for nic: %s, failed %d", nicname, len(rules)))
	res := rules[0].GetDstPort() == fmt.Sprintf("%d", lb.LoadBalancerPort)
	Expect(res).To(BeTrue(), fmt.Sprintf("found lb: %+v rule destip fail, %s:%s", lb, rules[0].GetDstPort(), fmt.Sprintf("%d", lb.LoadBalancerPort)))

	res = rules[0].GetDstIp() == lb.Vip+"/32"
	Expect(res).To(BeTrue(), fmt.Sprintf("found lb: %+v rule destip fail, %s:%s", lb, rules[0].GetDstIp(), lb.Vip+"/32"))
}
