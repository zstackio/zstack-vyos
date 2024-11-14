package plugintest

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"zstack-vyos/plugin"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"zstack-vyos/utils"
)

var _ = Describe("policyRoute test", func() {

	Context("vpc linux policyRoute test", func() {
		env := NewVpcIpv4Env()
		It("policyRoute: test preparing", func() {
			env.SetupBootStrap()
		})

		It("policyRoute: test system policy route", func() {
			/*
				example, vrouter has 2 public nics, 2 private nics:
				"ruleSets":[
					{"ruleSetName":"ZS-PR-RS-180","system":true},
					{"ruleSetName":"ZS-PR-RS-181","system":true}],
				"rules":[
					{"ruleNumber":1,"sourceIp":"192.168.9.0/24","state":"enable","tableNumber":181,"ruleSetName":"ZS-PR-RS-181"}],
				"tableNumbers":[181],
				"routes":[
					{"tableNumber":181,"distance":0,"destinationCidr":"192.168.9.0/24","nextHopIp":"192.168.9.248"},
					{"tableNumber":181,"distance":0,"destinationCidr":"192.168.2.0/24","outNicMic":"fa:e4:56:b2:95:02"},
					{"tableNumber":181,"distance":0,"destinationCidr":"0.0.0.0/0","nextHopIp":"192.168.9.1","outNicMic":"fa:ef:ce:25:13:04"},
					{"tableNumber":181,"distance":0,"destinationCidr":"192.168.10.0/24","outNicMic":"fa:93:84:a2:22:03"}],
				"refs":[{"ruleSetName":"ZS-PR-RS-181","mac":"fa:ef:ce:25:13:04"}],
				"markConntrack":true,
			*/
			var cmd plugin.SyncPolicyRouteCmd
			cmd.RuleSets = []plugin.PolicyRuleSetInfo{
				{RuleSetName: "ZS-PR-RS-180", System: true},
				{RuleSetName: "ZS-PR-RS-181", System: true},
			}
			addr1 := fmt.Sprintf("%v/24", env.additionalPubNicForUT1.Ip)
			_, cidr1, _ := net.ParseCIDR(addr1)
			addr3 := fmt.Sprintf("%v/24", env.PriNicForUT.Ip)
			_, cidr3, _ := net.ParseCIDR(addr3)
			addr4 := fmt.Sprintf("%v/24", env.PriNicForUT1.Ip)
			_, cidr4, _ := net.ParseCIDR(addr4)

			cmd.Rules = []plugin.PolicyRuleInfo{
				{RuleSetName: "ZS-PR-RS-181", RuleNumber: 1, SourceIp: cidr1.String(), TableNumber: 181, State: "enable"},
			}
			cmd.TableNumbers = []int{181}
			cmd.Routes = []plugin.PolicyRouteInfo{
				{TableNumber: 181, DestinationCidr: cidr1.String(), NextHopIp: env.additionalPubNicForUT1.Gateway},
				{TableNumber: 181, DestinationCidr: cidr3.String(), NextHopIp: env.PriNicForUT.Gateway, OutNicMic: env.PriNicForUT.Mac},
				{TableNumber: 181, DestinationCidr: cidr4.String(), NextHopIp: env.PriNicForUT1.Gateway, OutNicMic: env.PriNicForUT1.Mac},
				{TableNumber: 181, DestinationCidr: "0.0.0.0/0", NextHopIp: env.additionalPubNicForUT1.Gateway},
			}
			cmd.Refs = []plugin.PolicyRuleSetNicRef{
				{RuleSetName: "ZS-PR-RS-181", Mac: env.additionalPubNicForUT1.Mac},
			}
			cmd.MarkConntrack = true

			plugin.ApplyPolicyRoutes(&cmd)
			checkSystemPolicyRouteIpRule(true, env)
			checkSystemPolicyRouteRouteEntry(true, env)
			//checkSystemPolicyRouteIptables(true)

			delCmd := plugin.SyncPolicyRouteCmd{}
			plugin.ApplyPolicyRoutes(&delCmd)
			checkSystemPolicyRouteIpRule(false, env)
			checkSystemPolicyRouteRouteEntry(false, env)
			//checkSystemPolicyRouteIptables(false)
		})

		/*
			It("policyRoute: test policy route for service chain", func() {
				var cmd plugin.SyncPolicyRouteCmd
				cmd.RuleSets = []plugin.PolicyRuleSetInfo{
					{RuleSetName: "ZS-PR-RS-1", System: false},
					{RuleSetName: "ZS-PR-RS-2", System: false},
				}
				addr3 := fmt.Sprintf("%v/24", env.PriNicForUT.Ip)
				_, cidr3, _ := net.ParseCIDR(addr3)

				cmd.Rules = []plugin.PolicyRuleInfo{
					{RuleSetName: "ZS-PR-RS-1", RuleNumber: 1001, TableNumber: 100, State: "enable"},
					{RuleSetName: "ZS-PR-RS-2", RuleNumber: 1002, TableNumber: 101, State: "enable", DestIp: addr3},
				}
				cmd.TableNumbers = []int{100, 101}
				cmd.Routes = []plugin.PolicyRouteInfo{
					{TableNumber: 100, DestinationCidr: "0.0.0.0/0", NextHopIp: env.PriNicForUT1.Gateway},
					{TableNumber: 100, DestinationCidr: cidr3.String(), NextHopIp: env.PriNicForUT.Gateway, OutNicMic: env.PriNicForUT.Mac},
					{TableNumber: 101, DestinationCidr: cidr3.String(), NextHopIp: env.PriNicForUT1.Gateway},
				}
				cmd.Refs = []plugin.PolicyRuleSetNicRef{
					{RuleSetName: "ZS-PR-RS-1", Mac: env.PriNicForUT.Mac},
					{RuleSetName: "ZS-PR-RS-2", Mac: env.PriNicForUT1.Mac},
				}
				cmd.MarkConntrack = false

				plugin.ApplyPolicyRoutes(&cmd)
				checkServiceChainIpRule(true)
				checkServiceChainRouteEntry(true, env)
				//checkServiceChainIptables(true)

				delCmd := plugin.SyncPolicyRouteCmd{}
				plugin.ApplyPolicyRoutes(&delCmd)
				checkServiceChainIpRule(false)
				checkServiceChainRouteEntry(false, env)
				//checkServiceChainIptables(false)
			})*/

		It("policy_route : destroying", func() {
			env.DestroyBootStrap()
		})
	})

})

func checkSystemPolicyRouteIpRule(exist bool, env *VpcIp4Env) {
	rules := utils.GetZStackIpRules()

	cidr, err := utils.NetmaskToCIDR(env.additionalPubNicForUT1.Netmask)
	utils.PanicOnError(err)
	addr1 := fmt.Sprintf("%v/%v", env.additionalPubNicForUT1.Ip, cidr)
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
			Expect(found).To(BeTrue(), fmt.Sprintf("ip rule not found %+v", r))
		} else {
			Expect(found).To(BeFalse(), fmt.Sprintf("ip rule found %+v", r))
		}
	}
}

func checkSystemPolicyRouteRouteEntry(exist bool, env *VpcIp4Env) {
	routes := utils.GetCurrentRouteEntries(181)

	log.Debugf("routes: %+v", routes)
	cidr, err := utils.NetmaskToCIDR(env.PriNicForUT.Netmask)
	utils.PanicOnError(err)
	addr1 := fmt.Sprintf("%v/%v", env.PriNicForUT.Ip, cidr)
	_, cidr1, _ := net.ParseCIDR(addr1)

	cidr, err = utils.NetmaskToCIDR(env.PriNicForUT1.Netmask)
	utils.PanicOnError(err)
	addr2 := fmt.Sprintf("%v/%v", env.PriNicForUT1.Ip, cidr)
	_, cidr2, _ := net.ParseCIDR(addr2)

	cidr, err = utils.NetmaskToCIDR(env.additionalPubNicForUT1.Netmask)
	utils.PanicOnError(err)
	addr3 := fmt.Sprintf("%v/%v", env.additionalPubNicForUT1.Ip, cidr)
	_, cidr3, _ := net.ParseCIDR(addr3)

	expectRoutes := []utils.ZStackRouteEntry{
		{TableId: 181, DestinationCidr: "0.0.0.0/0", NextHopIp: env.additionalPubNicForUT1.Gateway},
		{TableId: 181, DestinationCidr: cidr1.String(), NextHopIp: env.PriNicForUT.Gateway},
		{TableId: 181, DestinationCidr: cidr2.String(), NextHopIp: env.PriNicForUT1.Gateway},
		{TableId: 181, DestinationCidr: cidr3.String(), NextHopIp: env.additionalPubNicForUT1.Gateway},
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
			Expect(found).To(BeTrue(), fmt.Sprintf("route entry not found %+v", r))
		} else {
			Expect(found).To(BeFalse(), fmt.Sprintf("route entry found %+v", r))
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
			Expect(found).To(BeTrue(), fmt.Sprintf("ip rule not found %+v", r))
		} else {
			Expect(found).To(BeFalse(), fmt.Sprintf("ip rule found %+v", r))
		}
	}
}

func checkServiceChainRouteEntry(exist bool, env *VpcIp4Env) {
	routes := utils.GetCurrentRouteEntries(100)
	route101 := utils.GetCurrentRouteEntries(101)
	routes = append(routes, route101...)

	cidr, err := utils.NetmaskToCIDR(env.PriNicForUT.Netmask)
	utils.PanicOnError(err)
	addr3 := fmt.Sprintf("%v/%v", env.PriNicForUT.Ip, cidr)
	_, cidr3, _ := net.ParseCIDR(addr3)

	expectRoutes := []utils.ZStackRouteEntry{
		{TableId: 100, DestinationCidr: "0.0.0.0/0", NextHopIp: env.PriNicForUT1.Gateway},
		{TableId: 100, DestinationCidr: cidr3.String(), NextHopIp: env.PriNicForUT.Gateway, NicName: env.PriNicForUT.Name},
		{TableId: 101, DestinationCidr: cidr3.String(), NextHopIp: env.PriNicForUT1.Gateway},
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
			Expect(found).To(BeTrue(), fmt.Sprintf("route entry not found %+v", r))
		} else {
			Expect(found).To(BeFalse(), fmt.Sprintf("route entry found %+v", r))
		}
	}
}

/*
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
}*/
