package plugin

import (
	"fmt"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("eip_test", func() {
	It("eip test preparing", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"eip_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		configureAllNicsForUT()
	})

	It("test create eip", func() {
		ipInPubL3, _ := utils.GetFreePubL3Ip()
		eip1 := eipInfo{VipIp: ipInPubL3, PublicMac: utils.PubNicForUT.Mac,
			GuestIp: "192.168.1.200", PrivateMac: utils.PrivateNicsForUT[0].Mac,
			SnatInboundTraffic: false}
		cmd1 := setEipCmd{Eip: eip1}
		log.Debugf("TestCreateEip createEip eip1: %+v", eip1)
		createEip(&cmd1)
		checkEipConfig(eip1)
		checkEipGroupAddress(eip1, true)

		// eip1, and eip2 share same guestIp
		ipInPubL3_2, _ := utils.GetFreePubL3Ip()
		eip2 := eipInfo{VipIp: ipInPubL3_2, PublicMac: utils.PubNicForUT.Mac,
			GuestIp: "192.168.1.200", PrivateMac: utils.PrivateNicsForUT[0].Mac,
			SnatInboundTraffic: false}
		cmd2 := setEipCmd{Eip: eip2}
		log.Debugf("TestCreateEip createEip eip2: %+v", eip2)
		createEip(&cmd2)
		checkEipConfig(eip2)
		checkEipGroupAddress(eip2, true)

		log.Debugf("TestCreateEip createEip again eip1: %+v", eip1)
		createEip(&cmd1)
		checkEipConfig(eip1)
		checkEipGroupAddress(eip1, true)
		log.Debugf("TestCreateEip createEip again eip2: %+v", eip2)
		createEip(&cmd2)
		checkEipConfig(eip2)
		checkEipGroupAddress(eip2, true)

		scmd := &syncEipCmd{Eips: []eipInfo{eip1, eip2}}
		log.Debugf("TestCreateEip syncEip eip1: %+v", scmd)
		syncEip(scmd)
		checkEipConfig(eip1)
		checkEipGroupAddress(eip1, true)
		checkEipConfig(eip2)
		checkEipGroupAddress(eip2, true)

		log.Debugf("TestCreateEip syncEip eip1: %+v", scmd)
		syncEip(scmd)
		checkEipConfig(eip1)
		checkEipGroupAddress(eip1, true)
		checkEipConfig(eip2)
		checkEipGroupAddress(eip2, true)

		rcmd1 := &removeEipCmd{Eip: eip1}
		log.Debugf("TestCreateEip removeEip eip1: %+v", eip1)
		removeEip(rcmd1)
		checkEipDelete(eip1)
		checkEipConfig(eip2)
		checkEipGroupAddress(eip1, true) // because eip1, eip2 share same guestIp, so guest should still in config

		log.Debugf("TestCreateEip removeEip eip1: %+v", eip1)
		removeEip(rcmd1)
		checkEipDelete(eip1)
		checkEipConfig(eip2)
		checkEipGroupAddress(eip1, true) // because eip1, eip2 share same guestIp, so guest should still in config

		log.Debugf("TestCreateEip removeEip eip2: %+v", eip2)
		rcmd2 := &removeEipCmd{Eip: eip2}
		removeEip(rcmd2)
		checkEipDelete(eip2)
		checkEipGroupAddress(eip2, false)

		log.Debugf("TestCreateEip removeEip eip2: %+v", eip2)
		removeEip(rcmd2)
		checkEipDelete(eip2)
		checkEipGroupAddress(eip2, false)

		utils.ReleasePubL3Ip(ipInPubL3)
		utils.ReleasePubL3Ip(ipInPubL3_2)
	})

	It("destroying env", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkEipConfig(eip eipInfo) {
	tree := server.NewParserFromShowConfiguration().Tree

	des := makeEipDescription(eip)
	pubNic, _ := utils.GetNicNameByMac(eip.PublicMac)
	privNic, _ := utils.GetNicNameByMac(eip.PrivateMac)

	/* check eip snat rule */
	rules := tree.Getf("nat source rule")
	gomega.Expect(rules).NotTo(gomega.BeNil(), "eip check failed, because get nat source rule failed")

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

		cmd := fmt.Sprintf("nat source rule %s outbound-interface %s", ruleId, pubNic)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("eip snat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("nat source rule %s source address %s", ruleId, eip.GuestIp)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("eip snat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("nat source rule %s translation address %s", ruleId, eip.VipIp)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("eip snat rule [%s] check failed", cmd))
	}

	gomega.Expect(ruleId).NotTo(gomega.BeNil(), fmt.Sprintf("eip [%+v] snat rule check failed", eip))

	/* check eip dnat rule */
	rules = tree.Getf("nat destination rule")
	gomega.Expect(rules).NotTo(gomega.BeNil(), "eip check failed, because get nat destination rule failed")

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

		cmd := fmt.Sprintf("nat destination rule %s inbound-interface any", ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("eip dnat rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("nat destination rule %s destination address %s", ruleId, eip.VipIp)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip dnat rule [%s] check failed", cmd)

		cmd = fmt.Sprintf("nat destination rule %s translation address %s", ruleId, eip.GuestIp)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip dnat rule [%s] check failed", cmd)
	}

	gomega.Expect(ruleId).NotTo(gomega.Equal(""), "eip [%+v] dnat rule check failed", eip)

	/* check eip public firewall */
	eipPubMacFirewallDes := "zstack-pub-eip-firewall-rule"
	rules = tree.Getf("firewall name %s.in rule", pubNic)
	gomega.Expect(ruleId).NotTo(gomega.Equal(""), "eip [%+v] dnat rule check failed", eip)

	ruleId = ""
	for _, rule := range rules.Children() {
		for _, r := range rule.Children() {
			if r.Name() == "description" && len(r.Values()) == 1 && r.Values()[0] == eipPubMacFirewallDes {
				ruleId = rule.Name()
				break
			}
		}

		if ruleId == "" {
			continue
		}

		cmd := fmt.Sprintf("firewall name %s.in rule %s action accept", pubNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip rule [%s] check failed", cmd)

		cmd = fmt.Sprintf("firewall name %s.in rule %s destination group address-group eip-group", pubNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip rule [%s] check failed", cmd)

		cmd = fmt.Sprintf("firewall name %s.in rule %s state established enable", pubNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip rule [%s] check failed", cmd)

		cmd = fmt.Sprintf("firewall name %s.in rule %s state new enable", pubNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip rule [%s] check failed", cmd)

		cmd = fmt.Sprintf("firewall name %s.in rule %s state related enable", pubNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip rule [%s] check failed", cmd)
	}

	gomega.Expect(ruleId).NotTo(gomega.Equal(""), "eip [%+v] public firewall rule check failed", eip)

	/* check eip private firewall */
	eipPriMacFirewallDes := "zstack-pri-eip-firewall-rule"
	rules = tree.Getf("firewall name %s.in rule", privNic)
	gomega.Expect(rules).NotTo(gomega.BeNil(), "eip check failed, get: [firewall name %s.in rule] failed", privNic)

	ruleId = ""
	for _, rule := range rules.Children() {
		for _, r := range rule.Children() {
			if r.Name() == "description" && len(r.Values()) == 1 && r.Values()[0] == eipPriMacFirewallDes {
				ruleId = rule.Name()
				break
			}
		}

		if ruleId == "" {
			continue
		}

		cmd := fmt.Sprintf("firewall name %s.in rule %s action accept", privNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip rule [%s] check failed", cmd)

		cmd = fmt.Sprintf("firewall name %s.in rule %s source group address-group eip-group", privNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip rule [%s] check failed", cmd)

		cmd = fmt.Sprintf("firewall name %s.in rule %s state established enable", privNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip rule [%s] check failed", cmd)

		cmd = fmt.Sprintf("firewall name %s.in rule %s state new enable", privNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip rule [%s] check failed", cmd)

		cmd = fmt.Sprintf("firewall name %s.in rule %s state related enable", privNic, ruleId)
		rule = tree.Get(cmd)
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip rule [%s] check failed", cmd)
	}

	gomega.Expect(ruleId).NotTo(gomega.Equal(""), "eip [%+v] private firewall rule check failed", eip)
}

func checkEipDelete(eip eipInfo) {
	tree := server.NewParserFromShowConfiguration().Tree

	des := makeEipDescription(eip)

	/* check eip snat rule */
	r := tree.FindSnatRuleDescription(des)
	gomega.Expect(r).To(gomega.BeNil(), "eip [%+v] snat delete failed", eip)

	/* check eip dnat rule */
	gomega.Expect(r).To(gomega.BeNil(), "eip [%+v] dnat delete failed", eip)

	/* check eip public firewall will not be deleted, only firewall address group
	    rule 4002 {
	     action accept
	     description zstack-pri-eip-firewall-rule
	     source {
	         group {
	             address-group eip-group
	         }
	     }
	     state {
	         established enable
	         new enable
	         related enable
	     }
	   }
	*/
}

func checkEipGroupAddress(eip eipInfo, exist bool) {
	tree := server.NewParserFromShowConfiguration().Tree
	cmd := fmt.Sprintf("firewall group address-group eip-group address %s", eip.GuestIp)
	rule := tree.Get(cmd)
	if exist {
		gomega.Expect(rule).NotTo(gomega.BeNil(), "eip group address [%s] added failed", cmd)
	} else {
		gomega.Expect(rule).To(gomega.BeNil(), "eip group address [%s] delete failed", cmd)
	}
}
