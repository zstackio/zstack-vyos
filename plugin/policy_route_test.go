package plugin

import (
	"fmt"
	"net"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"zstack-vyos/utils"
)

var _ = XDescribe("policy_route_test", func() {
	var nicCmd *configureNicCmd

	It("policy_route : test preparing", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"policy_route_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
	})

	It("policy_route : test system policy route", func() {
		nicCmd = &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.AdditionalPubNicsForUT[0])
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[1])
		configureNic(nicCmd)

		log.Debugf("###########test system policy route")
		var cmd syncPolicyRouteCmd
		cmd.RuleSets = []policyRuleSetInfo{
			{RuleSetName: "ZS-PR-RS-180", System: true},
			{RuleSetName: "ZS-PR-RS-181", System: true},
		}
		cidr, err := utils.NetmaskToCIDR(utils.AdditionalPubNicsForUT[0].Netmask)
		utils.PanicOnError(err)
		addr1 := fmt.Sprintf("%v/%v", utils.AdditionalPubNicsForUT[0].Ip, cidr)
		_, cidr1, _ := net.ParseCIDR(addr1)
		cidr, err = utils.NetmaskToCIDR(utils.PrivateNicsForUT[0].Netmask)
		utils.PanicOnError(err)
		addr3 := fmt.Sprintf("%v/%v", utils.PrivateNicsForUT[0].Ip, cidr)
		_, cidr3, _ := net.ParseCIDR(addr3)
		cidr, err = utils.NetmaskToCIDR(utils.PrivateNicsForUT[1].Netmask)
		utils.PanicOnError(err)
		addr4 := fmt.Sprintf("%v/%v", utils.PrivateNicsForUT[1].Ip, cidr)
		_, cidr4, _ := net.ParseCIDR(addr4)

		cmd.Rules = []policyRuleInfo{
			{RuleSetName: "ZS-PR-RS-181", RuleNumber: 1, SourceIp: cidr1.String(), TableNumber: 181, State: "enable"},
		}
		cmd.TableNumbers = []int{181}
		cmd.Routes = []policyRouteInfo{
			{TableNumber: 181, DestinationCidr: cidr1.String(), NextHopIp: utils.AdditionalPubNicsForUT[0].Gateway},
			{TableNumber: 181, DestinationCidr: cidr3.String(), NextHopIp: utils.PrivateNicsForUT[0].Gateway, OutNicMic: utils.PrivateNicsForUT[0].Mac},
			{TableNumber: 181, DestinationCidr: cidr4.String(), NextHopIp: utils.PrivateNicsForUT[1].Gateway, OutNicMic: utils.PrivateNicsForUT[1].Mac},
			{TableNumber: 181, DestinationCidr: "0.0.0.0/0", NextHopIp: utils.AdditionalPubNicsForUT[0].Gateway},
		}
		cmd.Refs = []policyRuleSetNicRef{
			{RuleSetName: "ZS-PR-RS-181", Mac: utils.AdditionalPubNicsForUT[0].Mac},
		}
		cmd.MarkConntrack = true

		applyPolicyRoutes(&cmd)
		checkSystemPolicyRouteIpRule(true)
		checkSystemPolicyRouteRouteEntry(true)
		checkSystemPolicyRouteIptables(true)

		delCmd := syncPolicyRouteCmd{}
		applyPolicyRoutes(&delCmd)
		checkSystemPolicyRouteIpRule(false)
		checkSystemPolicyRouteRouteEntry(false)
		checkSystemPolicyRouteIptables(false)
	})

	It("policy_route : test policy route for service chain", func() {
		log.Debugf("###########test policy route for service chain")
		/* this case refer to http://confluence.zstack.io/pages/viewpage.action?pageId=111070432 */
		var cmd syncPolicyRouteCmd
		cmd.RuleSets = []policyRuleSetInfo{
			{RuleSetName: "ZS-PR-RS-1", System: false},
			{RuleSetName: "ZS-PR-RS-2", System: false},
		}
		cidr, err := utils.NetmaskToCIDR(utils.PrivateNicsForUT[0].Netmask)
		utils.PanicOnError(err)
		addr3 := fmt.Sprintf("%v/%v", utils.PrivateNicsForUT[0].Ip, cidr)
		_, cidr3, _ := net.ParseCIDR(addr3)

		cmd.Rules = []policyRuleInfo{
			{RuleSetName: "ZS-PR-RS-1", RuleNumber: 1001, TableNumber: 100, State: "enable"},
			{RuleSetName: "ZS-PR-RS-2", RuleNumber: 1002, TableNumber: 101, State: "enable", DestIp: addr3},
		}
		cmd.TableNumbers = []int{100, 101}
		cmd.Routes = []policyRouteInfo{
			{TableNumber: 100, DestinationCidr: "0.0.0.0/0", NextHopIp: utils.PrivateNicsForUT[1].Gateway + "0"},
			{TableNumber: 100, DestinationCidr: cidr3.String(), NextHopIp: utils.PrivateNicsForUT[0].Gateway, OutNicMic: utils.PrivateNicsForUT[0].Mac},
			{TableNumber: 101, DestinationCidr: cidr3.String(), NextHopIp: utils.PrivateNicsForUT[1].Gateway + "0"},
		}
		cmd.Refs = []policyRuleSetNicRef{
			{RuleSetName: "ZS-PR-RS-1", Mac: utils.PrivateNicsForUT[0].Mac},
			{RuleSetName: "ZS-PR-RS-2", Mac: utils.AdditionalPubNicsForUT[0].Mac},
		}
		cmd.MarkConntrack = false

		applyPolicyRoutes(&cmd)
		checkServiceChainIpRule(true)
		checkServiceChainRouteEntry(true)
		checkServiceChainIptables(true)

		delCmd := syncPolicyRouteCmd{}
		applyPolicyRoutes(&delCmd)
		checkServiceChainIpRule(false)
		checkServiceChainRouteEntry(false)
		checkServiceChainIptables(false)
	})

	It("policy_route : destroying", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkSystemPolicyRouteIpRule(exist bool) {
	rules := utils.GetZStackIpRules()

	cidr, err := utils.NetmaskToCIDR(utils.AdditionalPubNicsForUT[0].Netmask)
	utils.PanicOnError(err)
	addr1 := fmt.Sprintf("%v/%v", utils.AdditionalPubNicsForUT[0].Ip, cidr)
	_, cidr1, _ := net.ParseCIDR(addr1)
	expectRules := []utils.ZStackIpRule{
		{Fwmark: 181, TableId: 181},
		{From: cidr1.String(), TableId: 181},
	}

	for _, r := range expectRules {
		found := false
		for _, o := range rules {
			if r.Equal(o) {
				found = true
				break
			}
		}

		if exist {
			gomega.Expect(found).To(gomega.BeTrue(), fmt.Sprintf("ip rule not found %+v", r))
		} else {
			gomega.Expect(found).To(gomega.BeFalse(), fmt.Sprintf("ip rule found %+v", r))
		}
	}
}

func checkSystemPolicyRouteRouteEntry(exist bool) {
	routes := utils.GetCurrentRouteEntries(181)

	cidr, err := utils.NetmaskToCIDR(utils.PrivateNicsForUT[0].Netmask)
	utils.PanicOnError(err)
	addr1 := fmt.Sprintf("%v/%v", utils.PrivateNicsForUT[0].Ip, cidr)
	_, cidr1, _ := net.ParseCIDR(addr1)

	cidr, err = utils.NetmaskToCIDR(utils.PrivateNicsForUT[1].Netmask)
	utils.PanicOnError(err)
	addr2 := fmt.Sprintf("%v/%v", utils.PrivateNicsForUT[1].Ip, cidr)
	_, cidr2, _ := net.ParseCIDR(addr2)

	cidr, err = utils.NetmaskToCIDR(utils.AdditionalPubNicsForUT[0].Netmask)
	utils.PanicOnError(err)
	addr3 := fmt.Sprintf("%v/%v", utils.AdditionalPubNicsForUT[0].Ip, cidr)
	_, cidr3, _ := net.ParseCIDR(addr3)

	expectRoutes := []utils.ZStackRouteEntry{
		{TableId: 181, DestinationCidr: "0.0.0.0/0", NextHopIp: utils.AdditionalPubNicsForUT[0].Gateway},
		{TableId: 181, DestinationCidr: cidr1.String(), NicName: utils.PrivateNicsForUT[0].Name},
		{TableId: 181, DestinationCidr: cidr2.String(), NicName: utils.PrivateNicsForUT[1].Name},
		{TableId: 181, DestinationCidr: cidr3.String(), NicName: utils.AdditionalPubNicsForUT[0].Name},
	}

	for _, r := range expectRoutes {
		found := false
		for _, o := range routes {
			if err := r.Equal(o); err == nil {
				found = true
				break
			}
		}

		if exist {
			gomega.Expect(found).To(gomega.BeTrue(), fmt.Sprintf("route entry not found %+v", r))
		} else {
			gomega.Expect(found).To(gomega.BeFalse(), fmt.Sprintf("route entry found %+v", r))
		}
	}
}

func checkSystemPolicyRouteIptables(exist bool) {
	table := utils.NewIpTables(utils.MangleTable)

	var expectRules []*utils.IpTableRule
	rule := utils.NewIpTableRule(utils.PREROUTING.String())
	rule.SetAction(utils.IPTABLES_ACTION_CONNMARK_RESTORE).SetCompareTarget(true)
	expectRules = append(expectRules, rule)

	rule = utils.NewIpTableRule(utils.PREROUTING.String())
	rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetMarkType(utils.IptablesMarkNotMatch).SetMark(0)
	expectRules = append(expectRules, rule)

	rule = utils.NewIpTableRule(utils.PREROUTING.String()).SetCompareTarget(true)
	rule.SetAction(getPolicyRouteSetChainName("ZS-PR-RS-181")).SetInNic(utils.AdditionalPubNicsForUT[0].Name)
	expectRules = append(expectRules, rule)

	rule = utils.NewIpTableRule(getPolicyRouteSetChainName("ZS-PR-RS-181"))
	rule.SetAction(getPolicyRouteTableChainName(181)).SetCompareTarget(true)
	expectRules = append(expectRules, rule)

	rule = utils.NewIpTableRule(getPolicyRouteTableChainName(181)).SetCompareTarget(true)
	rule.SetAction(utils.IPTABLES_ACTION_CONNMARK).SetTargetMark(181)
	expectRules = append(expectRules, rule)

	rule = utils.NewIpTableRule(getPolicyRouteTableChainName(181))
	rule.SetMarkType(utils.IptablesMarkMatch).SetMark(0).SetCompareTarget(true)
	rule.SetAction(utils.IPTABLES_ACTION_MARK).SetTargetMark(181)
	expectRules = append(expectRules, rule)

	for _, r := range expectRules {
		found := false
		for _, o := range table.Rules {
			if err := r.IsRuleEqual(o); err == nil {
				found = true
				break
			}
		}

		if exist {
			gomega.Expect(found).To(gomega.BeTrue(), fmt.Sprintf("iptable rules entry not found %+v", r))
		} else {
			gomega.Expect(found).To(gomega.BeFalse(), fmt.Sprintf("iptable rules found %+v", r))
		}
	}
}

func checkServiceChainIpRule(exist bool) {
	rules := utils.GetZStackIpRules()
	expectRules := []utils.ZStackIpRule{
		{Fwmark: 100, TableId: 100},
		{Fwmark: 101, TableId: 101},
	}

	for _, r := range expectRules {
		found := false
		for _, o := range rules {
			if r.Equal(o) {
				found = true
				break
			}
		}

		if exist {
			gomega.Expect(found).To(gomega.BeTrue(), fmt.Sprintf("ip rule not found %+v", r))
		} else {
			gomega.Expect(found).To(gomega.BeFalse(), fmt.Sprintf("ip rule found %+v", r))
		}
	}
}

func checkServiceChainRouteEntry(exist bool) {
	routes := utils.GetCurrentRouteEntries(100)
	route101 := utils.GetCurrentRouteEntries(101)
	routes = append(routes, route101...)

	cidr, err := utils.NetmaskToCIDR(utils.PrivateNicsForUT[0].Netmask)
	utils.PanicOnError(err)
	addr3 := fmt.Sprintf("%v/%v", utils.PrivateNicsForUT[0].Ip, cidr)
	_, cidr3, _ := net.ParseCIDR(addr3)

	expectRoutes := []utils.ZStackRouteEntry{
		{TableId: 100, DestinationCidr: "0.0.0.0/0", NextHopIp: utils.PrivateNicsForUT[1].Gateway + "0"},
		{TableId: 100, DestinationCidr: cidr3.String(), NextHopIp: utils.PrivateNicsForUT[0].Gateway, NicName: utils.PrivateNicsForUT[0].Name},
		{TableId: 101, DestinationCidr: cidr3.String(), NextHopIp: utils.PrivateNicsForUT[1].Gateway + "0"},
	}

	for _, r := range expectRoutes {
		found := false
		for _, o := range routes {
			if err := r.Equal(o); err == nil {
				found = true
				break
			}
		}

		if exist {
			gomega.Expect(found).To(gomega.BeTrue(), fmt.Sprintf("route entry not found %+v", r))
		} else {
			gomega.Expect(found).To(gomega.BeFalse(), fmt.Sprintf("route entry found %+v", r))
		}
	}
}

func checkServiceChainIptables(exist bool) {
	table := utils.NewIpTables(utils.MangleTable)

	cidr, err := utils.NetmaskToCIDR(utils.PrivateNicsForUT[0].Netmask)
	utils.PanicOnError(err)
	addr3 := fmt.Sprintf("%v/%v", utils.PrivateNicsForUT[0].Ip, cidr)
	_, cidr3, _ := net.ParseCIDR(addr3)

	var expectRules []*utils.IpTableRule

	rule := utils.NewIpTableRule(utils.PREROUTING.String()).SetCompareTarget(true)
	rule.SetAction(getPolicyRouteSetChainName("ZS-PR-RS-1")).SetInNic(utils.PrivateNicsForUT[0].Name)
	expectRules = append(expectRules, rule)

	rule = utils.NewIpTableRule(getPolicyRouteSetChainName("ZS-PR-RS-1"))
	rule.SetAction(getPolicyRouteTableChainName(100)).SetCompareTarget(true)
	expectRules = append(expectRules, rule)

	rule = utils.NewIpTableRule(getPolicyRouteTableChainName(100))
	rule.SetAction(utils.IPTABLES_ACTION_MARK).SetTargetMark(100).SetCompareTarget(true)
	rule.SetMarkType(utils.IptablesMarkMatch).SetMark(0)
	expectRules = append(expectRules, rule)

	rule = utils.NewIpTableRule(utils.PREROUTING.String()).SetCompareTarget(true)
	rule.SetAction(getPolicyRouteSetChainName("ZS-PR-RS-2")).SetInNic(utils.AdditionalPubNicsForUT[0].Name)
	expectRules = append(expectRules, rule)

	rule = utils.NewIpTableRule(getPolicyRouteSetChainName("ZS-PR-RS-2"))
	rule.SetAction(getPolicyRouteTableChainName(101)).SetCompareTarget(true)
	rule.SetDstIp(cidr3.String())
	expectRules = append(expectRules, rule)

	rule = utils.NewIpTableRule(getPolicyRouteTableChainName(101))
	rule.SetAction(utils.IPTABLES_ACTION_MARK).SetTargetMark(101).SetCompareTarget(true)
	rule.SetMarkType(utils.IptablesMarkMatch).SetMark(0)
	expectRules = append(expectRules, rule)

	for _, r := range expectRules {
		found := false
		for _, o := range table.Rules {
			if err := r.IsRuleEqual(o); err == nil {
				found = true
				break
			}
		}

		if exist {
			gomega.Expect(found).To(gomega.BeTrue(), fmt.Sprintf("iptable rules entry not found %+v", r))
		} else {
			gomega.Expect(found).To(gomega.BeFalse(), fmt.Sprintf("iptable rules found %+v", r))
		}
	}

	var unExpectRules []*utils.IpTableRule
	rule = utils.NewIpTableRule(utils.PREROUTING.String())
	rule.SetAction(utils.IPTABLES_ACTION_CONNMARK).SetCompareTarget(true)
	unExpectRules = append(unExpectRules, rule)

	rule = utils.NewIpTableRule(utils.PREROUTING.String())
	rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetMarkType(utils.IptablesMarkNotMatch).SetMark(0)
	unExpectRules = append(unExpectRules, rule)

	for _, r := range unExpectRules {
		found := false
		for _, o := range table.Rules {
			if err := r.IsRuleEqual(o); err == nil {
				found = true
				break
			}
		}

		gomega.Expect(found).To(gomega.BeFalse(), fmt.Sprintf("iptable rules found %+v", r))
	}
}
