package plugin

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
)

func setTestDnsEnv() {
	utils.InitLog(utils.VYOS_UT_LOG_FOLDER+"dns_test.log", false)
}

var _ = Describe("dns_test", func() {
	var nicCmd *configureNicCmd

	It("dns test preparing", func() {
		setTestDnsEnv()
		nicCmd = &configureNicCmd{}
	})

	It("test set dns", func() {
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)
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
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)
		cmd := &setDnsCmd{}
		dns := &dnsInfo{}

		dns.DnsAddress = "223.5.5.5"
		dns.NicMac = utils.PubNicForUT.Mac

		cmd.Dns = []dnsInfo{*dns}
		setDns(cmd)

		removeCmd := &removeDnsCmd{}
		removeCmd.Dns = []dnsInfo{*dns}
		removeDns(removeCmd)

		gomega.Expect(checkDnsProcess()).NotTo(gomega.BeTrue(), "dnsmasq start failed")

		checkFirewall(utils.PubNicForUT, false)
	})

	It("dns test destroying", func() {
		removeNic(nicCmd)
	})
})

func checkDnsProcess() bool {
	bash := utils.Bash{
		Command: fmt.Sprintf("ps -ef|grep dnsmasq|grep -v grep"),
	}

	code, _, _, _ := bash.RunWithReturn()

	if code == 0 {
		return true
	} else {
		return false
	}
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
