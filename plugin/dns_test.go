package plugin

import (
	"fmt"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

var _ = Describe("dns_test", func() {

	It("dns test preparing", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"dns_test.log", false)
		utils.CleanTestEnvForUT()
		configureAllNicsForUT()
		if utils.IsSkipVyosIptables() {
			By("is skip iptables")
		}
	})

	It("test set dns", func() {
		cmd := &setDnsCmd{}
		dns := &dnsInfo{}

		dns.DnsAddress = "223.5.5.5"
		dns.NicMac = utils.PubNicForUT.Mac

		cmd.Dns = []dnsInfo{*dns}

		setDns(cmd)

		gomega.Expect(checkDnsProcess()).To(gomega.BeTrue(), "dnsmasq start failed")

		checkFirewall(utils.PubNicForUT, true)
	})

	It("test remove dns", func() {
		cmd := &setDnsCmd{}
		dns := &dnsInfo{}

		dns.DnsAddress = "223.5.5.5"
		dns.NicMac = utils.PubNicForUT.Mac

		cmd.Dns = []dnsInfo{*dns}
		setDns(cmd)

		removeCmd := &removeDnsCmd{}
		removeCmd.Dns = []dnsInfo{*dns}
		removeDns(removeCmd)

		gomega.Expect(checkDnsProcess()).To(gomega.BeTrue(), "dnsmasq should be running")

		checkFirewall(utils.PubNicForUT, false)
	})

	It("test add vpcdns and check config", func() {
		vpcCmd1 := &setVpcDnsCmd{
			Dns:    []string{"223.5.5.5"},
			NicMac: []string{utils.PubNicForUT.Mac, utils.PrivateNicsForUT[0].Mac},
		}
		err := setVpcDns(vpcCmd1)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("setVpcDns() should reture nil, but %+v", err))

		pid1, err := utils.ReadPidFromFile(DNSMASQ_PID_FILE)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("read dnsmasq pid file error: %+v", err))
		gomega.Expect(checkDnsProcess()).To(gomega.BeTrue(), "dnsmasq should be running")
		gomega.Expect(diffConfigFile(DNSMASQ_PID_FILE_TEMP, DNSMASQ_PID_FILE)).To(gomega.BeTrue(), "dnsmasq pid file should be exist")

		vpcCmd2 := &setVpcDnsCmd{
			Dns:    []string{"8.8.8.8", "223.5.5.5"},
			NicMac: []string{utils.PubNicForUT.Mac, utils.PrivateNicsForUT[0].Mac},
		}
		err = setVpcDns(vpcCmd2)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("setVpcDns() should reture nil, but %+v", err))
		pid2, err := utils.ReadPidFromFile(DNSMASQ_PID_FILE)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("read dnsmasq pid file error: %+v", err))
		gomega.Expect(checkDnsProcess()).To(gomega.BeTrue(), "dnsmasq should be running")
		gomega.Expect(diffConfigFile(DNSMASQ_PID_FILE_TEMP, DNSMASQ_PID_FILE)).To(gomega.BeTrue(), "dnsmasq pid file should be exist")

		gomega.Expect(pid1).To(gomega.Equal(pid2), fmt.Sprintf("pid1[%d] should equal pid2[%d], but not", pid1, pid2))

		vpcCmd3 := &setVpcDnsCmd{
			Dns:    []string{},
			NicMac: []string{utils.PubNicForUT.Mac, utils.PrivateNicsForUT[0].Mac},
		}
		err = setVpcDns(vpcCmd3)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("setVpcDns() should reture nil, but %+v", err))
		pid3, err := utils.ReadPidFromFile(DNSMASQ_PID_FILE)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("read dnsmasq pid file error: %+v", err))
		gomega.Expect(checkDnsProcess()).To(gomega.BeTrue(), "dnsmasq should be running")

		gomega.Expect(pid2).To(gomega.Equal(pid3), fmt.Sprintf("pid2[%d] should equal pid3[%d], but not", pid2, pid3))

		vpcCmd4 := &setVpcDnsCmd{
			Dns:    []string{"8.8.8.8", "223.5.5.5"},
			NicMac: []string{utils.PubNicForUT.Mac},
		}
		err = setVpcDns(vpcCmd4)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("setVpcDns() should reture nil, but %+v", err))
		pid4, err := utils.ReadPidFromFile(DNSMASQ_PID_FILE)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("read dnsmasq pid file error: %+v", err))
		gomega.Expect(checkDnsProcess()).To(gomega.BeTrue(), "dnsmasq should be running")

		gomega.Expect(pid3).NotTo(gomega.Equal(pid4), fmt.Sprintf("pid3[%d] should not equal pid4[%d]", pid3, pid4))

		vpcCmd5 := &setVpcDnsCmd{
			Dns:    []string{"8.8.8.8", "223.5.5.5"},
			NicMac: []string{},
		}
		err = setVpcDns(vpcCmd5)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("setVpcDns() should reture nil, but %+v", err))
		gomega.Expect(checkDnsProcess()).NotTo(gomega.BeTrue(), "dnsmasq should be stop")
	})

	It("dns test destroying", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkDnsProcess() bool {
	bash := utils.Bash{
		Command: fmt.Sprintf("ps -ef | grep '%s' | grep -v grep", DNSMASQ_BIN_PATH),
		Sudo:    true,
	}
	ret, _, _, _ := bash.RunWithReturn()

	return ret == 0
}

func checkFirewall(nic utils.NicInfo, start bool) {
	tree := server.NewParserFromShowConfiguration().Tree
	rules := tree.Getf("firewall name %s.local rule", nic.Name)
	ruleExsit := false
	for _, rule := range rules.Children() {
		ruleId := rule.Name()
		if ruleId == "" {
			continue
		}

		cmd := fmt.Sprintf("firewall name %s.local rule %s description %s", nic.Name, ruleId, makeDnsFirewallRuleDescription(nic.Name))
		rule = tree.Get(cmd)
		if rule != nil {
			ruleExsit = true
		}
	}

	if start {
		gomega.Expect(ruleExsit).To(gomega.BeTrue(), "dns test: check firewall rule fail")
	} /*else {
	    gomega.Expect(ruleExsit).NotTo(gomega.BeTrue(), "dns test: check firewall rule fail")
	}*/
}
