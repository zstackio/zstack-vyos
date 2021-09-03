package plugin

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/zstackio/zstack-vyos/utils/test"
	"strings"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
)

var _ = Describe("dnat test", func() {
	var nicCmd *configureNicCmd
	var ipInPubL3 string
	var ipInPubL32 string
	var rule1 dnatInfo
	var rule2 dnatInfo
	var rule3 dnatInfo
	var setCmd *setDnatCmd
	
	It("config nic for snat test", func() {
		utils.InitLog(test.VYOS_UT_LOG_FOLDER+"dnat_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		nicCmd = &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, test.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, test.PrivateNicsForUT[0])
		configureNic(nicCmd)

		ipInPubL3, _ = test.GetFreePubL3Ip()
		ipInPubL32, _ = test.GetFreePubL3Ip()

		rule1 = dnatInfo{Uuid: "uuid1", VipPortStart: 100, VipPortEnd: 65530,
			PrivatePortStart: 101, PrivatePortEnd: 65531, ProtocolType: "TCP", VipIp: ipInPubL3,
			PublicMac: test.PubNicForUT.Mac, PrivateIp: "192.168.1.100", PrivateMac: test.PrivateNicsForUT[0].Mac,
			AllowedCidr: "1.1.1.0/24", SnatInboundTraffic: false}
		rule2 = dnatInfo{Uuid: "uuid2", VipPortStart: 100, VipPortEnd: 65530,
			PrivatePortStart: 101, PrivatePortEnd: 65531, ProtocolType: "UDP", VipIp: ipInPubL3,
			PublicMac: test.PubNicForUT.Mac, PrivateIp: "192.168.1.50", PrivateMac: test.PrivateNicsForUT[0].Mac,
			AllowedCidr: "1.1.1.0/24", SnatInboundTraffic: false}

		rule3 = dnatInfo{Uuid: "uuid1", VipPortStart: 22, VipPortEnd: 22,
			PrivatePortStart: 22, PrivatePortEnd: 22, ProtocolType: "TCP", VipIp: ipInPubL32,
			PublicMac: test.PubNicForUT.Mac, PrivateIp: "192.168.1.200", PrivateMac: test.PrivateNicsForUT[0].Mac,
			AllowedCidr: "1.1.2.0/24", SnatInboundTraffic: false}
	})

	It("setDnat", func() {
		setCmd := &setDnatCmd{Rules: []dnatInfo{rule1, rule2}}
		log.Debugf("add dnat 1 %+v", setCmd)
		setDnat(setCmd)
		checkDnatConfig(rule1)
		checkDnatConfig(rule2)
	})

	It("setDnat again", func() {
		setCmd := &setDnatCmd{Rules: []dnatInfo{rule1, rule2}}
		log.Debugf("add dnat 2 %+v", setCmd)
		rule1.PrivateIp = "192.168.1.101"
		setDnat(setCmd)
		checkDnatConfig(rule1)
		checkDnatConfig(rule2)
	})

	It("add dnat rule", func() {
		rule3 := dnatInfo{Uuid: "uuid1", VipPortStart: 22, VipPortEnd: 22,
			PrivatePortStart: 22, PrivatePortEnd: 22, ProtocolType: "TCP", VipIp: ipInPubL32,
			PublicMac: test.PubNicForUT.Mac, PrivateIp: "192.168.1.200", PrivateMac: test.PrivateNicsForUT[0].Mac,
			AllowedCidr: "1.1.2.0/24", SnatInboundTraffic: false}
		setCmd = &setDnatCmd{Rules: []dnatInfo{rule3}}
		log.Debugf("add dnat 3 %+v", setCmd)
		setDnat(setCmd)
		checkDnatConfig(rule1)
		checkDnatConfig(rule2)
		checkDnatConfig(rule3)
	})

	It("sync dnat", func() {
		scmd := &syncDnatCmd{Rules: []dnatInfo{rule1, rule2, rule3}}
		log.Debugf("sync dnat 1 %+v", scmd)
		syncDnat(scmd)
		checkDnatConfig(rule1)
		checkDnatConfig(rule2)
		checkDnatConfig(rule3)
	})

	It("sync dnat again", func() {
		scmd := &syncDnatCmd{Rules: []dnatInfo{rule2, rule3}}
		log.Debugf("sync dnat 2 %+v", scmd)
		syncDnat(scmd)
		checkDnatConfigDelete(rule1)
		checkDnatConfig(rule2)
		checkDnatConfig(rule3)
	})

	It("remove dnat", func() {
		rcmd := removeDnatCmd{Rules: []dnatInfo{rule2, rule3}}
		log.Debugf("remove dnat 1 %+v", rcmd)
		removeDnat(&rcmd)
		checkDnatConfigDelete(rule2)
		checkDnatConfigDelete(rule3)
	})
	
	It("release ip after test", func() {
		test.ReleasePubL3Ip(ipInPubL3)
		test.ReleasePubL3Ip(ipInPubL32)
	})
})

func checkDnatConfig(pf dnatInfo) {
	tree := server.NewParserFromShowConfiguration().Tree

	des := makeDnatDescription(pf)
	pubNic, _ := utils.GetNicNameByMac(pf.PublicMac)
	var sport string
	if pf.VipPortStart == pf.VipPortEnd {
		sport = fmt.Sprintf("%v", pf.VipPortStart)
	} else {
		sport = fmt.Sprintf("%v-%v", pf.VipPortStart, pf.VipPortEnd)
	}

	var dport string
	if pf.PrivatePortStart == pf.PrivatePortEnd {
		dport = fmt.Sprintf("%v", pf.PrivatePortStart)
	} else {
		dport = fmt.Sprintf("%v-%v", pf.PrivatePortStart, pf.PrivatePortEnd)
	}

	/* check pf rule */
	rules := tree.Getf("nat destination rule")
	gomega.Expect(rules).NotTo(gomega.BeNil(), fmt.Sprintf("port forwarding check failed, because get nat destination rule failed"))

	ruleId := ""
	for _, rule := range rules.Children() {
		for _, r := range rule.Children() {
			if r.Name() == "description" && len(r.Values()) == 1 && r.Values()[0] == des {
				ruleId = rule.Name()
				break
			}
		}

		if ruleId == "" {
			continue
		}

		cmd := fmt.Sprintf("nat destination rule %s inbound-interface any", ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("nat destination rule %s destination address %s", ruleId, pf.VipIp)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("nat destination rule %s destination port %s", ruleId, sport)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("nat destination rule %s translation address %s", ruleId, pf.PrivateIp)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("nat destination rule %s translation port %s", ruleId, dport)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))
	}

	gomega.Expect(ruleId == "").NotTo(gomega.BeTrue(), fmt.Sprintf("dnat rule check failed"))

	/* check port forwarding public firewall */
	rules = tree.Getf("firewall name %s.in rule", pubNic)
	gomega.Expect(rules).NotTo(gomega.BeNil(), fmt.Sprintf("dnat check failed, get: [firewall name %s.in rule] failed", pubNic))
	ruleId = ""
	for _, rule := range rules.Children() {
		for _, r := range rule.Children() {
			if r.Name() == "description" && len(r.Values()) == 1 && r.Values()[0] == des {
				ruleId = rule.Name()
				break
			}
		}

		if ruleId == "" {
			continue
		}

		cmd := fmt.Sprintf("firewall name %s.in rule %s action accept", pubNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("firewall name %s.in rule %s destination address %s", pubNic, ruleId, pf.PrivateIp)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("firewall name %s.in rule %s destination port %s", pubNic, ruleId, dport)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("firewall name %s.in rule %s protocol %s", pubNic, ruleId, strings.ToLower(pf.ProtocolType))
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("firewall name %s.in rule %s source address %s", pubNic, ruleId, pf.AllowedCidr)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("firewall name %s.in rule %s state new enable", pubNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))
	}

	gomega.Expect(ruleId).NotTo(gomega.BeEmpty(), fmt.Sprintf("pf [%+v] public firewall rule check failed, ruleId %s", pf, ruleId))

	/* check allow cidr  */
	if pf.AllowedCidr != "" && pf.AllowedCidr != "0.0.0.0/0" {
		rules = tree.Getf("firewall name %s.in rule", pubNic)
		gomega.Expect(rules).NotTo(gomega.BeNil(), fmt.Sprintf("eip check failed, get: [firewall name %s.in rule] failed", pubNic))

		ruleId = ""
		reject := makeAllowCidrRejectDescription(pf)
		for _, rule := range rules.Children() {
			for _, r := range rule.Children() {
				if r.Name() == "description" && len(r.Values()) == 1 && r.Values()[0] == reject {
					ruleId = rule.Name()
					break
				}
			}

			if ruleId == "" {
				continue
			}

			cmd := fmt.Sprintf("firewall name %s.in rule %s action reject", pubNic, ruleId)
			rule = tree.Get(cmd)
			gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

			cmd = fmt.Sprintf("firewall name %s.in rule %s destination address %s", pubNic, ruleId, pf.PrivateIp)
			rule = tree.Get(cmd)
			gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

			cmd = fmt.Sprintf("firewall name %s.in rule %s destination port %s", pubNic, ruleId, dport)
			rule = tree.Get(cmd)
			gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

			cmd = fmt.Sprintf("firewall name %s.in rule %s protocol %s", pubNic, ruleId, strings.ToLower(pf.ProtocolType))
			rule = tree.Get(cmd)
			gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

			cmd = fmt.Sprintf("firewall name %s.in rule %s source address !%s", pubNic, ruleId, pf.AllowedCidr)
			rule = tree.Get(cmd)
			gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))

			cmd = fmt.Sprintf("firewall name %s.in rule %s state new enable", pubNic, ruleId)
			rule = tree.Get(cmd)
			gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("dnat rule [%s] check failed", cmd))
		}

		gomega.Expect(ruleId == "").NotTo(gomega.BeTrue(), fmt.Sprintf("pf [%+v] public firewall rule check failed", pf))
	}
}

func checkDnatConfigDelete(pf dnatInfo) {
	tree := server.NewParserFromShowConfiguration().Tree

	des := makeDnatDescription(pf)
	pubNic, _ := utils.GetNicNameByMac(pf.PublicMac)

	/* check dnat rule */
	rules := tree.Getf("nat destination rule")
	if rules == nil {
		return
	}

	ruleId := ""
	for _, rule := range rules.Children() {
		for _, r := range rule.Children() {
			if r.Name() == "description" && len(r.Values()) == 1 && r.Values()[0] == des {
				ruleId = rule.Name()
				break
			}
		}

		if ruleId == "" {
			continue
		}
	}

	gomega.Expect(ruleId != "").NotTo(gomega.BeTrue(), fmt.Sprintf("dnat rule delete failed"))

	/* check port forwarding public firewall */
	for _, rule := range rules.Children() {
		for _, r := range rule.Children() {
			if r.Name() == "description" && len(r.Values()) == 1 && r.Values()[0] == des {
				ruleId = rule.Name()
				break
			}
		}

		if ruleId == "" {
			continue
		}
	}

	gomega.Expect(ruleId != "").NotTo(gomega.BeTrue(), fmt.Sprintf("pf [%+v] public firewall rule delete failed", pf))

	/* check allow cidr  */
	if pf.AllowedCidr != "" && pf.AllowedCidr != "0.0.0.0/0" {
		rules = tree.Getf("firewall name %s.in rule", pubNic)
		if rules == nil {
			return
		}

		ruleId = ""
		reject := makeAllowCidrRejectDescription(pf)
		for _, rule := range rules.Children() {
			for _, r := range rule.Children() {
				if r.Name() == "description" && len(r.Values()) == 1 && r.Values()[0] == reject {
					ruleId = rule.Name()
					break
				}
			}

			if ruleId == "" {
				continue
			}
		}

		gomega.Expect(ruleId != "").NotTo(gomega.BeTrue(), fmt.Sprintf("pf [%+v] public allowcidr rule delete failed", pf))
	}
}
