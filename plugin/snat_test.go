package plugin

import (
	"fmt"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

var _ = Describe("snat_test", func() {
	var sinfo1, sinfo2 snatInfo

	It("test snat pre env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"snat_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(false)
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
	})

	It("test set snat", func() {
		cmd := &setSnatCmd{Snat: sinfo1}
		setSnat(cmd)
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[0])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], true)

		// setsnat again, config not changed
		setSnat(cmd)
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[0])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], true)

		cmd = &setSnatCmd{Snat: sinfo2}
		setSnat(cmd)
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[1])
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[0])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], true)
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], true)

		rcmd := removeSnatCmd{NatInfo: []snatInfo{sinfo2, sinfo1}}
		removeSnat(&rcmd)
		checkSnatRuleDel(utils.PrivateNicsForUT[0])
		checkSnatRuleDel(utils.PrivateNicsForUT[1])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], false)
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], false)
	})

	It("test set snat state", func() {
		cmd := &setSnatStateCmd{Snats: []snatInfo{sinfo1, sinfo2}}

		sinfo1.State = true
		sinfo2.State = true
		cmd = &setSnatStateCmd{Snats: []snatInfo{sinfo1, sinfo2}}
		cmd.Enable = true
		setSnatState(cmd)
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[0])
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[1])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], true)
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], true)

		// set snat enable again
		setSnatState(cmd)
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[0])
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[1])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], true)
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], true)

		// set snat disable
		sinfo1.State = false
		sinfo2.State = false
		cmd = &setSnatStateCmd{Snats: []snatInfo{sinfo1, sinfo2}}
		cmd.Enable = false
		setSnatState(cmd)
		checkSnatRuleDel(utils.PrivateNicsForUT[0])
		checkSnatRuleDel(utils.PrivateNicsForUT[1])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], false)
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], false)

		// set snat disable again
		setSnatState(cmd)
		checkSnatRuleDel(utils.PrivateNicsForUT[0])
		checkSnatRuleDel(utils.PrivateNicsForUT[1])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], false)
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], false)
	})

	It("test sync snat state", func() {
		cmd := &syncSnatCmd{Snats: []snatInfo{sinfo1, sinfo2}}

		// sync snat with disable flag, if snat is not enabled
		sinfo1.State = false
		sinfo2.State = false
		cmd = &syncSnatCmd{Snats: []snatInfo{sinfo1, sinfo2}}
		cmd.Enable = false
		syncSnat(cmd)
		checkSnatRuleDel(utils.PrivateNicsForUT[0])
		checkSnatRuleDel(utils.PrivateNicsForUT[1])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], false)
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], false)

		sinfo1.State = true
		sinfo2.State = true
		cmd = &syncSnatCmd{Snats: []snatInfo{sinfo1, sinfo2}}
		cmd.Enable = true
		syncSnat(cmd)
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[0])
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[1])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], true)
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], true)

		// sync snat again
		syncSnat(cmd)
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[0])
		checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[1])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], true)
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], true)

		// sync snat disable
		sinfo1.State = false
		sinfo2.State = false
		cmd = &syncSnatCmd{Snats: []snatInfo{sinfo1, sinfo2}}
		cmd.Enable = false
		syncSnat(cmd)
		checkSnatRuleDel(utils.PrivateNicsForUT[0])
		checkSnatRuleDel(utils.PrivateNicsForUT[1])
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], false)
		checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], false)
	})

	It("test sync snat state again", func() {
		cmd := &syncSnatCmd{Snats: []snatInfo{sinfo1, sinfo2}}

		for i := 0; i < 10; i++ {
			sinfo1.State = true
			sinfo2.State = true
			cmd = &syncSnatCmd{Snats: []snatInfo{sinfo1, sinfo2}}
			cmd.Enable = true
			syncSnat(cmd)
			checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[0])
			checkSnatRuleSet(utils.PubNicForUT, utils.PrivateNicsForUT[1])
			checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], true)
			checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], true)

			// sync snat disable
			sinfo1.State = false
			sinfo2.State = false
			cmd = &syncSnatCmd{Snats: []snatInfo{sinfo1, sinfo2}}
			cmd.Enable = false
			syncSnat(cmd)
			checkSnatRuleDel(utils.PrivateNicsForUT[0])
			checkSnatRuleDel(utils.PrivateNicsForUT[1])
			checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[0], false)
			checkSnatVyosIpTables(utils.PubNicForUT, utils.PrivateNicsForUT[1], false)
		}
	})

	It("snat_test clean env", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkSnatRuleSet(pub, pri utils.NicInfo) {
	tree := server.NewParserFromShowConfiguration().Tree

	priNicNum, _ := utils.GetNicNumber(pri.Name)
	pubNicRuleNo, priNicRuleNo := getNicSNATRuleNumber(priNicNum)
	cidr, _ := utils.GetNetworkNumber(pri.Ip, pri.Netmask)

	cmd := fmt.Sprintf("nat source rule %d outbound-interface %s", pubNicRuleNo, pub.Name)
	rule := tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), "snat rule [%s] check failed", cmd)

	cmd = fmt.Sprintf("nat source rule %d source address %s", pubNicRuleNo, cidr)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), "snat rule [%s] check failed", cmd)

	cmd = fmt.Sprintf("nat source rule %d translation address %s", pubNicRuleNo, pub.Ip)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), "snat rule [%s] check failed", cmd)

	cmd = fmt.Sprintf("nat source rule %d outbound-interface %s", priNicRuleNo, pri.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), "snat rule [%s] check failed", cmd)

	cmd = fmt.Sprintf("nat source rule %d source address %s", priNicRuleNo, cidr)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), "snat rule [%s] check failed", cmd)

	cmd = fmt.Sprintf("nat source rule %d translation address %s", priNicRuleNo, pub.Ip)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), "snat rule [%s] check failed", cmd)
}

func checkSnatRuleDel(pri utils.NicInfo) {
	tree := server.NewParserFromShowConfiguration().Tree
	priNicNum, _ := utils.GetNicNumber(pri.Name)
	pubNicRuleNo, priNicRuleNo := getNicSNATRuleNumber(priNicNum)

	rule := tree.Get(fmt.Sprintf("nat source rule %d", pubNicRuleNo))
	gomega.Expect(rule).To(gomega.BeNil(), "snat rule [%d] delete failed", pubNicRuleNo)

	rule = tree.Get(fmt.Sprintf("nat source rule %d", priNicRuleNo))
	gomega.Expect(rule).To(gomega.BeNil(), "snat rule [%d] delete failed", priNicRuleNo)
}

func checkSnatVyosIpTables(pub, pri utils.NicInfo, add bool) {
	priNicNum, _ := utils.GetNicNumber(pri.Name)
	pubNicRuleNo, priNicRuleNo := getNicSNATRuleNumber(priNicNum)
	cidr, _ := utils.GetNetworkNumber(pri.Ip, pri.Netmask)

	cmd := fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s ! -d 224.0.0.0/8 -o %s -m comment --comment SRC-NAT-%d -j SNAT --to-source %s",
		cidr, pub.Name, pubNicRuleNo, pub.Ip)
	bash := utils.Bash{
		Command: cmd,
		Sudo:    true,
	}
	ret, _, _, err := bash.RunWithReturn()
	if add {
		gomega.Expect(ret).To(gomega.Equal(0), "vyos iptables rule [%s] add failed, ret = %d, err = %v", cmd, ret, err)
		gomega.Expect(err).To(gomega.BeNil(), "vyos iptables rule [%s] add failed, ret = %d, err = %v", cmd, ret, err)

	} else {
		gomega.Expect(ret).NotTo(gomega.Equal(0), "vyos iptables rule [%s] del failed, ret = %d, err = %v", cmd, ret, err)
		gomega.Expect(err).NotTo(gomega.BeNil(), "vyos iptables rule [%s] del failed, ret = %d, err = %v", cmd, ret, err)
	}

	cmd = fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s ! -d 224.0.0.0/8 -o %s -m comment --comment SRC-NAT-%d -j SNAT --to-source %s",
		cidr, pri.Name, priNicRuleNo, pub.Ip)
	bash = utils.Bash{
		Command: cmd,
		Sudo:    true,
	}
	if add {
		gomega.Expect(ret).To(gomega.Equal(0), "vyos iptables rule [%s] add failed, ret = %d, err = %v", cmd, ret, err)
		gomega.Expect(err).To(gomega.BeNil(), "vyos iptables rule [%s] add failed, ret = %d, err = %v", cmd, ret, err)
	} else {
		gomega.Expect(ret).NotTo(gomega.Equal(0), "vyos iptables rule [%s] del failed, ret = %d, err = %v", cmd, ret, err)
		gomega.Expect(err).NotTo(gomega.BeNil(), "vyos iptables rule [%s] del failed, ret = %d, err = %v", cmd, ret, err)
	}
}
