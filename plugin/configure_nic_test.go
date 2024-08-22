package plugin

import (
	"fmt"

	server "zstack-vyos/server"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("configure_nic_test", func() {
	var cmd *configureNicCmd
	var sinfo1, sinfo2 snatInfo

	It("configure_nic_test preparing", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"configure_nic_test.log", false)
		log.Debugf("############### prea env for configure_nic_test ###############")
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		cmd = &configureNicCmd{}
	})

	It("TestConfigureNic", func() {
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[1])
		cmd.Nics = append(cmd.Nics, utils.AdditionalPubNicsForUT[0])
		log.Debugf("############### TestConfigureNic ###############")
		configureNic(cmd)
		checkNicFirewall(utils.PrivateNicsForUT[0])
		checkNicFirewall(utils.PrivateNicsForUT[1])
		checkNicFirewall(utils.AdditionalPubNicsForUT[0])
	})

	It("TestConfigureNicFirewallDefaultAction", func() {
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[1])
		cmd.Nics = append(cmd.Nics, utils.AdditionalPubNicsForUT[0])
		log.Debugf("############### TestConfigureNicFirewallDefaultAction ###############")
		configureNic(cmd)
		checkNicFirewall(utils.PrivateNicsForUT[0])
		checkNicFirewall(utils.PrivateNicsForUT[1])
		checkNicFirewall(utils.AdditionalPubNicsForUT[0])

		for i, _ := range cmd.Nics {
			cmd.Nics[i].FirewallDefaultAction = "accept"
		}
		log.Debugf("############### TestConfigureNicFirewallDefaultAction accept ###############")
		configureNicDefaultAction(cmd)
		checkNicFirewall(cmd.Nics[0])
		checkNicFirewall(cmd.Nics[1])
		checkNicFirewall(cmd.Nics[2])
	})

	It("TestChangeDefaultNic", func() {
		cmd.Nics = append(cmd.Nics, utils.AdditionalPubNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.PubNicForUT)
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[1])
		log.Debugf("############### TestChangeDefaultNic ###############")
		configureNic(cmd)

		sinfo1 = snatInfo{
			PublicNicMac:  utils.AdditionalPubNicsForUT[0].Mac,
			PublicIp:      utils.AdditionalPubNicsForUT[0].Ip,
			PrivateNicMac: utils.PrivateNicsForUT[0].Mac,
			PrivateNicIp:  utils.PrivateNicsForUT[0].Ip,
			SnatNetmask:   utils.PrivateNicsForUT[0].Netmask,
		}

		sinfo2 = snatInfo{
			PublicNicMac:  utils.AdditionalPubNicsForUT[0].Mac,
			PublicIp:      utils.AdditionalPubNicsForUT[0].Ip,
			PrivateNicMac: utils.PrivateNicsForUT[1].Mac,
			PrivateNicIp:  utils.PrivateNicsForUT[1].Ip,
			SnatNetmask:   utils.PrivateNicsForUT[1].Netmask,
		}

		ccmd := &ChangeDefaultNicCmd{}
		ccmd.NewNic = utils.AdditionalPubNicsForUT[0]
		ccmd.Snats = []snatInfo{sinfo1, sinfo2}
		log.Debugf("############### TestChangeDefaultNic change default nic ###############")
		changeDefaultNic(ccmd)

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
		ccmd.NewNic = utils.PubNicForUT
		ccmd.Snats = []snatInfo{sinfo1, sinfo2}
		log.Debugf("############### TestChangeDefaultNic change default nic again ###############")
		changeDefaultNic(ccmd)

		rcmd := removeSnatCmd{NatInfo: []snatInfo{sinfo2, sinfo1}}
		removeSnat(&rcmd)
	})

	It("TestCheckNicIsUp", func() {
		log.Debugf("############### TestCheckNicIsUp for master ###############")
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[0])
		configureNic(cmd)
		err := checkNicIsUp(utils.PrivateNicsForUT[0].Name, false)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("nic [%s] shoud be up", utils.PrivateNicsForUT[0].Name))

		removeNic(cmd)
		log.Debugf("############### TestCheckNicIsUp for backup ###############")
		SetKeepalivedStatusForUt(KeepAlivedStatus_Backup)
		configureNic(cmd)
		err = checkNicIsUp(utils.PrivateNicsForUT[0].Name, false)
		gomega.Expect(err).NotTo(gomega.BeNil(), fmt.Sprintf("nic [%s] is should not up", utils.PrivateNicsForUT[0].Name))
		removeNic(cmd)
	})

	It("TestAddSecondaryIpFirewall", func() {
		log.Debugf("############### TestAddSecondaryIpFirewall ###############")
		cmd := &configureNicCmd{}
		cmd.Nics = append(cmd.Nics, utils.AdditionalPubNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.PubNicForUT)
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[1])
		configureNic(cmd)

		ipPubL3, _ := utils.GetFreePubL3Ip()
		addSecondaryIpFirewall(utils.PubNicForUT.Name, ipPubL3)

		checkSecondaryIpFirewall(utils.PubNicForUT, ipPubL3)

		utils.ReleasePubL3Ip(ipPubL3)
	})

	It("Test Add Ipv6 Nic and Delete", func() {
		log.Debugf("############### Test Add Ipv6 Nic and Delete ###############")
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		cmd := &configureNicCmd{}
		pubNic := utils.PubNicForUT
		privNic0 := utils.PrivateNicsForUT[0]
		privNic1 := utils.PrivateNicsForUT[1]
		cmd.Nics = append(cmd.Nics, pubNic)
		cmd.Nics = append(cmd.Nics, privNic0)
		cmd.Nics = append(cmd.Nics, privNic1)
		removeNic(cmd)
		cmd = &configureNicCmd{}

		pubNic.Ip6 = "2001::1"
		pubNic.PrefixLength = 64
		pubNic.AddressMode = "Stateless-DHCP"
		privNic0.Ip6 = "2001::2"
		privNic0.PrefixLength = 64
		privNic0.AddressMode = "Stateful-DHCP"
		privNic1.Ip6 = "2001::3"
		privNic1.PrefixLength = 64
		privNic1.AddressMode = "SLAAC"
		cmd.Nics = append(cmd.Nics, pubNic)
		cmd.Nics = append(cmd.Nics, privNic0)
		cmd.Nics = append(cmd.Nics, privNic1)
		cleanUpConfig()
		configureNic(cmd)
		checkRadvdStatus(cmd, false)
		isRunning := checkRadvdProcess()
		gomega.Expect(isRunning).To(gomega.BeTrue(), "radvd service should running")

		removeNic(cmd)
		checkRadvdStatus(cmd, true)
		isRunning = checkRadvdProcess()
		gomega.Expect(isRunning).To(gomega.BeFalse(), "radvd service should stop")
		cleanUpConfig()
	})

	It("configure_nic_test destroying", func() {
		utils.CleanTestEnvForUT()
	})
})

func configureAllNicsForUT() {
	nicCmd := &configureNicCmd{}
	nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
	nicCmd.Nics = append(nicCmd.Nics, utils.AdditionalPubNicsForUT[0])
	nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
	nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[1])
	configureNic(nicCmd)
	configureNicFirewall([]utils.NicInfo{utils.MgtNicForUT})
}

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

func checkNicFirewallDelete(nic utils.NicInfo) {
	tree := server.NewParserFromShowConfiguration().Tree
	cmd := fmt.Sprintf("firewall name %s.in", nic.Name)
	rule := tree.Get(cmd)
	gomega.Expect(rule).To(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] delete failed", cmd))

	cmd = fmt.Sprintf("firewall name %s.local", nic.Name)
	rule = tree.Get(cmd)
	gomega.Expect(rule).To(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] delete failed", cmd))
}

func checkSecondaryIpFirewall(nic utils.NicInfo, ip string) {
	tree := server.NewParserFromShowConfiguration().Tree
	des := makeNicFirewallDescription(nic.Name, ip)
	rules := tree.Getf("firewall name %s.local rule", nic.Name)
	gomega.Expect(rules).NotTo(gomega.BeNil(), fmt.Sprintf("nic [%s] secondary ip [%s] check failed", nic.Name, ip))

	num := 0
	for _, rule := range rules.Children() {
		ruleId := ""
		for _, r := range rule.Children() {
			if r.Name() == "description" && len(r.Values()) == 1 && r.Values()[0] == des {
				ruleId = rule.Name()
				break
			}
		}

		if ruleId == "" {
			continue
		}

		num++

		cmd := fmt.Sprintf("firewall name %s.local rule %s action accept", nic.Name, ruleId)
		rule = tree.Get(cmd)

		gomega.Expect(rules).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("firewall name %s.local rule %s destination address %s", nic.Name, ruleId, ip)
		rule = tree.Get(cmd)
		gomega.Expect(rules).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

		cmd = fmt.Sprintf("firewall name %s.local rule %s state established enable", nic.Name, ruleId)
		rule = tree.Get(cmd)
		if rule != nil {
			cmd = fmt.Sprintf("firewall name %s.local rule %s state related enable", nic.Name, ruleId)
			rule = tree.Get(cmd)
			gomega.Expect(rules).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))
		} else {
			cmd = fmt.Sprintf("firewall name %s.local rule %s protocol icmp", nic.Name, ruleId)
			rule = tree.Get(cmd)
			gomega.Expect(rules).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))
		}
	}

	gomega.Expect(num).To(gomega.Equal(2), fmt.Sprintf("nic [%s] secondary ip [%s] check failed, num = %d", nic.Name, ip, num))
}

func checkRadvdStatus(cmd *configureNicCmd, isDelete bool) {
	testMap := make(utils.RadvdAttrsMap)
	err := utils.JsonLoadConfig(utils.GetRadvdJsonFile(), &testMap)
	gomega.Expect(err).To(gomega.BeNil(), "load radvd json error: %s", err)

	for _, nic := range cmd.Nics {
		if nic.Ip6 != "" && nic.Category == "Private" {
			_, ok := testMap[nic.Name]
			if isDelete {
				gomega.Expect(ok).To(gomega.BeFalse(), "nic[%s] should not in json file", nic.Name)
			} else {
				gomega.Expect(ok).To(gomega.BeTrue(), "nic[%s] should in json file", nic.Name)
			}

		} else {
			_, ok := testMap[nic.Name]
			gomega.Expect(ok).To(gomega.BeFalse(), "public nic[%s] should not in json file", nic.Name)
		}
	}
}

func cleanUpConfig() {
	bash := utils.Bash{
		Command: "rm -f /home/vyos/zvr/.zstack_config/radvd; pkill -9 radvd",
		Sudo:    true,
	}
	bash.Run()
}

func checkRadvdProcess() bool {
	bash := utils.Bash{
		Command: fmt.Sprintf("ps -ef | grep '%s' | grep -v grep", utils.RADVD_BIN_PATH),
	}
	ret, _, _, _ := bash.RunWithReturn()

	return ret == 0
}
