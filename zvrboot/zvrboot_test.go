package main

import (
	"fmt"
	_ "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
	_ "strings"
)

var _ = Describe("zvrboot_test TestInitFirewall", func() {
	It("zvrboot_test", func() {
		/*
			utils.InitLog(utils.VYOS_UT_LOG_FOLDER + "zvrboot_test.log", false)
			waitIptablesServiceOnline()
			content := ``
			if err := json.Unmarshal([]byte(content), &bootstrapInfo); err != nil {
				panic(errors.Wrap(err, fmt.Sprintf("unable to JSON parse:\n %s", string(content))))
			}
			utils.InitVyosVersion()
			configureVyos()

			log.Debugf("############### TestConfigureVyos ###############")
			checkNicFirewall(utils.MgtNicForUT)
			checkNicFirewall(utils.PubNicForUT)
		*/
	})
})

func checkNicFirewall(nic utils.NicInfo) {
	tree := server.NewParserFromShowConfiguration().Tree
	cmd := fmt.Sprintf("firewall name %s.local default-action %s", nic.Name, nic.FirewallDefaultAction)
	rule := tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local rule 1 action accept", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local rule 1 destination address %s", nic.Name, nic.Ip)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local rule 1 state established enable", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local rule 1 state related enable", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local rule 2 action accept", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local rule 2 destination address %s", nic.Name, nic.Ip)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local rule 2 protocol icmp", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local rule 3 action reject", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local rule 3 destination address %s", nic.Name, nic.Ip)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local rule 3 destination port %d", nic.Name, int(utils.GetSshPortFromBootInfo()))
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local rule 3 protocol tcp", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.in default-action %s", nic.Name, nic.FirewallDefaultAction)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.in rule 4000 action accept", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.in rule 4000 state established enable", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.in rule 4000 state related enable", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.in rule 4000 action accept", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.in rule 9999 action accept", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.in rule 9999 state new enable", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.in rule 4001 state action accept", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).To(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.in rule 4001 protocol icmp", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).To(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))
}
