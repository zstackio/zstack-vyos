package plugin

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
	"github.com/zstackio/zstack-vyos/utils/test"
)

var sinfo1 snatInfo
var sinfo2 snatInfo

func init() {
	sinfo1 = snatInfo{
		PublicNicMac:  test.PubNicForUT.Mac,
		PublicIp:      test.PubNicForUT.Ip,
		PrivateNicMac: test.PrivateNicsForUT[0].Mac,
		PrivateNicIp:  test.PrivateNicsForUT[0].Ip,
		SnatNetmask:   test.PrivateNicsForUT[0].Netmask,
	}

	sinfo2 = snatInfo{
		PublicNicMac:  test.PubNicForUT.Mac,
		PublicIp:      test.PubNicForUT.Ip,
		PrivateNicMac: test.PrivateNicsForUT[1].Mac,
		PrivateNicIp:  test.PrivateNicsForUT[1].Ip,
		SnatNetmask:   test.PrivateNicsForUT[1].Netmask,
	}
}

var _ = Describe("snat_test", func() {
	BeforeEach(func() {
		utils.InitLog(test.VYOS_UT_LOG_FOLDER+"snat_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
	})

	It("test set snat", func() {
		cmd := &setSnatCmd{Snat: sinfo1}
		setSnat(cmd)
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[0])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], true)

		// setsnat again, config not changed
		setSnat(cmd)
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[0])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], true)

		cmd = &setSnatCmd{Snat: sinfo2}
		setSnat(cmd)
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[1])
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[0])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], true)
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], true)

		rcmd := removeSnatCmd{NatInfo: []snatInfo{sinfo2, sinfo1}}
		removeSnat(&rcmd)
		checkSnatRuleDel(test.PrivateNicsForUT[0])
		checkSnatRuleDel(test.PrivateNicsForUT[1])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], false)
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], false)
	})

	It("test set snat state", func() {
		cmd := &setSnatStateCmd{Snats: []snatInfo{sinfo1, sinfo2}}
		cmd.Enable = true
		setSnatState(cmd)
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[0])
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[1])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], true)
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], true)

		// set snat enable again
		setSnatState(cmd)
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[0])
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[1])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], true)
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], true)

		// set snat disable
		cmd.Enable = false
		setSnatState(cmd)
		checkSnatRuleDel(test.PrivateNicsForUT[0])
		checkSnatRuleDel(test.PrivateNicsForUT[1])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], false)
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], false)

		// set snat disable again
		setSnatState(cmd)
		checkSnatRuleDel(test.PrivateNicsForUT[0])
		checkSnatRuleDel(test.PrivateNicsForUT[1])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], false)
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], false)
	})

	It("test sync snat state", func() {
		cmd := &syncSnatCmd{Snats: []snatInfo{sinfo1, sinfo2}}

		// sync snat with disable flag, if snat is not enabled
		cmd.Enable = false
		syncSnat(cmd)
		checkSnatRuleDel(test.PrivateNicsForUT[0])
		checkSnatRuleDel(test.PrivateNicsForUT[1])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], false)
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], false)

		cmd.Enable = true
		syncSnat(cmd)
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[0])
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[1])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], true)
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], true)

		// sync snat again
		syncSnat(cmd)
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[0])
		checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[1])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], true)
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], true)

		// sync snat disable
		cmd.Enable = false
		syncSnat(cmd)
		checkSnatRuleDel(test.PrivateNicsForUT[0])
		checkSnatRuleDel(test.PrivateNicsForUT[1])
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], false)
		checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], false)
	})

	It("test sync snat state again", func() {
		cmd := &syncSnatCmd{Snats: []snatInfo{sinfo1, sinfo2}}

		for i := 0; i < 10; i++ {
			cmd.Enable = true
			syncSnat(cmd)
			checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[0])
			checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[1])
			checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], true)
			checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], true)

			// sync snat disable
			cmd.Enable = false
			syncSnat(cmd)
			checkSnatRuleDel(test.PrivateNicsForUT[0])
			checkSnatRuleDel(test.PrivateNicsForUT[1])
			checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[0], false)
			checkSnatVyosIpTables(test.PubNicForUT, test.PrivateNicsForUT[1], false)
		}
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
