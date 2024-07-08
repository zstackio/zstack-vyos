package plugin

import (
	"fmt"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("dhcp_iptables_test", func() {
	var nicCmd *configureNicCmd

	It("[IPTABLES]dhcp : test preparing", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"dhcp_iptables_test.log", false)
		utils.CleanTestEnvForUT()
		utils.SetSkipVyosIptablesForUT(true)
		nicCmd = &configureNicCmd{}
	})

	It("[IPTABLES]dhcp : test star dhcpServer", func() {
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		configureNic(nicCmd)

		dhcpServer1 := dhcpServer{
			NicMac:    utils.PubNicForUT.Mac,
			Mtu:       1500,
			Gateway:   "10.1.1.1",
			Netmask:   "255.255.255.0",
			DnsServer: "8.8.8.8",
		}
		dhcpInfo1 := dhcpInfo{
			Ip:                 "10.1.1.10",
			Dns:                []string{"10.1.1.1"},
			Mac:                "fa:bb:d2:8e:5c:11",
			Netmask:            "255.255.255.0",
			Gateway:            "10.1.1.1",
			Hostname:           "10-1-1-10",
			VrNicMac:           utils.PubNicForUT.Mac,
			IsDefaultL3Network: true,
			Mtu:                1600,
		}
		dhcpServer1.DhcpInfos = []dhcpInfo{dhcpInfo1}

		dhcpServer2 := dhcpServer{
			NicMac:    utils.PrivateNicsForUT[0].Mac,
			Mtu:       1600,
			Gateway:   "172.16.90.1",
			Netmask:   "255.255.255.0",
			DnsServer: "223.5.5.5",
		}
		dhcpInfo2 := dhcpInfo{
			Ip:                 "172.16.90.157",
			Dns:                []string{"172.16.90.1"},
			Mac:                "fa:bb:d2:8e:5c:02",
			Netmask:            "255.255.255.0",
			Gateway:            "172.16.90.1",
			Hostname:           "172-16-90-157",
			VrNicMac:           utils.PrivateNicsForUT[0].Mac,
			IsDefaultL3Network: false,
			Mtu:                1600,
		}
		dhcpServer2.DhcpInfos = []dhcpInfo{dhcpInfo2}

		startDhcpServer(dhcpServer1)
		checkDhcpFirewallIpTables(utils.PubNicForUT.Mac)
		startDhcpServer(dhcpServer2)
		checkDhcpFirewallIpTables(utils.PrivateNicsForUT[0].Mac)
	})

	It("[IPTABLES]dhcp : test destroying", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkDhcpFirewallIpTables(nicMac string) {
	nicName, err := utils.GetNicNameByMac(nicMac)
	utils.PanicOnError(err)

	table := utils.NewIpTables(utils.FirewallTable)

	rule1 := utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
	rule1.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule1.SetProto(utils.IPTABLES_PROTO_UDP).SetDstPort("67")

	rule2 := utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
	rule2.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule2.SetProto(utils.IPTABLES_PROTO_UDP).SetDstPort("68")

	rule3 := utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
	rule3.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule3.SetProto(utils.IPTABLES_PROTO_UDP).SetDstPort("53")

	rule4 := utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
	rule4.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule4.SetProto(utils.IPTABLES_PROTO_TCP).SetDstPort("68")

	res := table.Check(rule1)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule1.String()))

	res = table.Check(rule2)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule2.String()))

	res = table.Check(rule3)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule3.String()))

	res = table.Check(rule4)
	Expect(res).To(BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule4.String()))
}
