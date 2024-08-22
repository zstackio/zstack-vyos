package plugin

import (
	"fmt"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("dns_iptables_test", func() {
	var nicCmd *configureNicCmd
	It("[IPTABLES]dns : test preparing", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"dns_iptables_test.log", false)
		utils.CleanTestEnvForUT()
		utils.SetSkipVyosIptablesForUT(true)
		nicCmd = &configureNicCmd{}
	})

	It("[IPTABLES]dns : test setDns, should return nil", func() {
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		configureNic(nicCmd)

		cmd := &setDnsCmd{}
		dns1 := dnsInfo{
			DnsAddress: "114.114.114.114",
			NicMac:     utils.PubNicForUT.Mac,
		}
		dns2 := dnsInfo{
			DnsAddress: "110.110.110.110",
			NicMac:     utils.PrivateNicsForUT[0].Mac,
		}
		cmd.Dns = []dnsInfo{dns1, dns2}

		err := setDns(cmd)
		Expect(err).To(BeNil())
		checkDnsFirewallIpTables(utils.PubNicForUT.Mac)
		checkDnsFirewallIpTables(utils.PrivateNicsForUT[0].Mac)
	})

	It("[IPTABLES]dns : test setVpcDns, should return nil", func() {
		vpcCmd := &setVpcDnsCmd{}
		vpcCmd.Dns = append(vpcCmd.Dns, "8.8.8.8")
		vpcCmd.Dns = append(vpcCmd.Dns, "223.5.5.5")
		vpcCmd.NicMac = append(vpcCmd.NicMac, utils.PubNicForUT.Mac)
		vpcCmd.NicMac = append(vpcCmd.NicMac, utils.PrivateNicsForUT[0].Mac)
		err := setVpcDns(vpcCmd)
		Expect(err).To(BeNil())
		checkDnsFirewallIpTables(utils.PubNicForUT.Mac)
		checkDnsFirewallIpTables(utils.PrivateNicsForUT[0].Mac)
	})

	It("[IPTABLES]dns : destroying", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkDnsFirewallIpTables(nicMac string) {
	nicName, _ := utils.GetNicNameByMac(nicMac)
	table := utils.NewIpTables(utils.FirewallTable)

	rule := utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule.SetProto(utils.IPTABLES_PROTO_UDP).SetDstPort("53")

	rule2 := utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
	rule2.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule2.SetProto(utils.IPTABLES_PROTO_TCP).SetDstPort("53")

	res := table.Check(rule)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

	res2 := table.Check(rule)
	Expect(res2).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
}
