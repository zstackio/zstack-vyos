package plugin

import (
	"fmt"
	"strings"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("dnat_iptables_test", func() {
	var (
		nicCmd     *configureNicCmd
		ipInPubL3  string
		ipInPubL32 string
		rule1      dnatInfo
		rule2      dnatInfo
		rule3      dnatInfo
		setCmd     *setDnatCmd
	)

	It("[IPTABLES]DNAT : config nic for snat test", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"dnat_iptables_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
		nicCmd = &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		configureNic(nicCmd)

		ipInPubL3, _ = utils.GetFreePubL3Ip()
		ipInPubL32, _ = utils.GetFreePubL3Ip()

		rule1 = dnatInfo{Uuid: "uuid1", VipPortStart: 100, VipPortEnd: 65530,
			PrivatePortStart: 101, PrivatePortEnd: 65531, ProtocolType: "TCP", VipIp: ipInPubL3,
			PublicMac: utils.PubNicForUT.Mac, PrivateIp: "192.168.1.100", PrivateMac: utils.PrivateNicsForUT[0].Mac,
			AllowedCidr: "1.1.1.0/24", SnatInboundTraffic: false}
		rule2 = dnatInfo{Uuid: "uuid2", VipPortStart: 100, VipPortEnd: 65530,
			PrivatePortStart: 101, PrivatePortEnd: 65531, ProtocolType: "UDP", VipIp: ipInPubL3,
			PublicMac: utils.PubNicForUT.Mac, PrivateIp: "192.168.1.50", PrivateMac: utils.PrivateNicsForUT[0].Mac,
			AllowedCidr: "1.1.2.0/24", SnatInboundTraffic: false}

		rule3 = dnatInfo{Uuid: "uuid3", VipPortStart: 22, VipPortEnd: 22,
			PrivatePortStart: 22, PrivatePortEnd: 22, ProtocolType: "TCP", VipIp: ipInPubL32,
			PublicMac: utils.PubNicForUT.Mac, PrivateIp: "192.168.1.200", PrivateMac: utils.PrivateNicsForUT[0].Mac,
			AllowedCidr: "1.1.3.0/24", SnatInboundTraffic: false}
	})

	It("[IPTABLES]DNAT : setDnat", func() {
		setCmd := &setDnatCmd{Rules: []dnatInfo{rule1, rule2}}
		log.Debugf("add dnat 1 %+v", setCmd)
		setDnat(setCmd)
		checkPortForwardingRuleByIpTables(rule1, false)
		checkPortForwardingRuleByIpTables(rule2, false)
	})

	It("[IPTABLES]DNAT : setDnat again", func() {
		/* change the ip of private nic */
		rule1.PrivateIp = "192.168.1.101"
		setCmd := &setDnatCmd{Rules: []dnatInfo{rule1, rule2}}
		log.Debugf("add dnat 2 %+v", setCmd)
		setDnat(setCmd)
		checkPortForwardingRuleByIpTables(rule1, false)
		checkPortForwardingRuleByIpTables(rule2, false)
	})

	It("[IPTABLES]DNAT : add dnat rule", func() {
		setCmd = &setDnatCmd{Rules: []dnatInfo{rule3}}
		log.Debugf("add dnat 3 %+v", setCmd)
		setDnat(setCmd)
		checkPortForwardingRuleByIpTables(rule1, false)
		checkPortForwardingRuleByIpTables(rule2, false)
		checkPortForwardingRuleByIpTables(rule3, false)
	})

	It("[IPTABLES]DNAT : sync dnat", func() {
		scmd := &syncDnatCmd{Rules: []dnatInfo{rule1, rule2, rule3}}
		log.Debugf("sync dnat 1 %+v", scmd)
		syncDnat(scmd)
		checkPortForwardingRuleByIpTables(rule1, false)
		checkPortForwardingRuleByIpTables(rule2, false)
		checkPortForwardingRuleByIpTables(rule3, false)
	})

	It("[IPTABLES]DNAT : sync dnat again", func() {
		scmd := &syncDnatCmd{Rules: []dnatInfo{rule2, rule3}}
		log.Debugf("sync dnat 2 %+v", scmd)
		syncDnat(scmd)
		checkPortForwardingRuleByIpTables(rule1, true)
		checkPortForwardingRuleByIpTables(rule2, false)
		checkPortForwardingRuleByIpTables(rule3, false)
	})

	It("[IPTABLES]DNAT : remove dnat", func() {
		rcmd := removeDnatCmd{Rules: []dnatInfo{rule2, rule3}}
		log.Debugf("remove dnat 1 %+v", rcmd)
		removeDnat(&rcmd)
		checkPortForwardingRuleByIpTables(rule2, true)
		checkPortForwardingRuleByIpTables(rule3, true)
	})

	It("[IPTABLES]DNAT : release ip after test", func() {
		nicCmd = &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		removeNic(nicCmd)
		for i, _ := range nicCmd.Nics {
			checkNicFirewallDeleteByIpTables(nicCmd.Nics[i])
		}
		utils.ReleasePubL3Ip(ipInPubL3)
		utils.ReleasePubL3Ip(ipInPubL32)
		utils.SetSkipVyosIptablesForUT(false)
	})

	It("[IPTABLES]DNAT : clean test env", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkPortForwardingRuleByIpTables(pf dnatInfo, deleted bool) {
	filterTable := utils.NewIpTables(utils.FirewallTable)
	natTable := utils.NewIpTables(utils.NatTable)

	pubNicName, err := utils.GetNicNameByMac(pf.PublicMac)
	utils.PanicOnError(err)
	protocol := utils.IPTABLES_PROTO_TCP
	if strings.ToLower(pf.ProtocolType) != utils.IPTABLES_PROTO_TCP {
		protocol = utils.IPTABLES_PROTO_UDP
	}
	var portRange string
	var natPortRange string
	if pf.VipPortEnd != pf.VipPortStart {
		portRange = fmt.Sprintf("%d:%d", pf.PrivatePortStart, pf.PrivatePortEnd)
		natPortRange = fmt.Sprintf("%d:%d", pf.VipPortStart, pf.VipPortEnd)
	} else {
		portRange = fmt.Sprintf("%d", pf.PrivatePortStart)
		natPortRange = fmt.Sprintf("%d", pf.VipPortStart)
	}
	if pf.AllowedCidr != "" && pf.AllowedCidr != "0.0.0.0/0" {
		filterRule := utils.NewIpTableRule(utils.GetRuleSetName(pubNicName, utils.RULESET_IN))
		filterRule.SetAction(utils.IPTABLES_ACTION_REJECT).SetRejectType(utils.REJECT_TYPE_ICMP_UNREACHABLE)
		filterRule.SetComment(utils.PortFordingRuleComment)
		filterRule.SetSrcIp(fmt.Sprintf("! %s", pf.AllowedCidr)).SetDstIp(fmt.Sprintf("%s/32", pf.PrivateIp))
		filterRule.SetProto(protocol).SetDstPort(portRange).SetState([]string{utils.IPTABLES_STATE_NEW})
		res := filterTable.Check(filterRule)
		if deleted {
			gomega.Expect(res).To(gomega.BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))
		} else {
			gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))
		}
	}

	filterRule := utils.NewIpTableRule(utils.GetRuleSetName(pubNicName, utils.RULESET_IN))
	filterRule.SetAction(utils.IPTABLES_ACTION_RETURN)
	filterRule.SetComment(utils.PortFordingRuleComment)
	filterRule.SetDstIp(fmt.Sprintf("%s/32", pf.PrivateIp))
	filterRule.SetProto(protocol).SetDstPort(portRange).SetState([]string{utils.IPTABLES_STATE_NEW})
	res := filterTable.Check(filterRule)
	if deleted {
		gomega.Expect(res).To(gomega.BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))
	} else {
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))
	}

	natRule := utils.NewIpTableRule(utils.RULESET_DNAT.String())
	natRule.SetAction(utils.IPTABLES_ACTION_DNAT)
	natRule.SetComment(utils.PortFordingRuleComment)
	natRule.SetDstIp(fmt.Sprintf("%s/32", pf.VipIp))
	natRule.SetProto(protocol).SetDstPort(natPortRange)
	natRule.SetDnatTargetIp(pf.PrivateIp).SetDnatTargetPort(strings.Replace(portRange, ":", "-", -1))
	res = natTable.Check(natRule)
	if deleted {
		gomega.Expect(res).To(gomega.BeFalse(), fmt.Sprintf("nat rule [%s] check failed", natRule.String()))
	} else {
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("nat rule [%s] check failed", natRule.String()))
	}
}
