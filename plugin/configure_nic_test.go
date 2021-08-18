package plugin

import (
    "fmt"
    log "github.com/Sirupsen/logrus"
    . "github.com/onsi/ginkgo"
    gomega "github.com/onsi/gomega"
    server "github.com/zstackio/zstack-vyos/server"
    "github.com/zstackio/zstack-vyos/utils"
    test "github.com/zstackio/zstack-vyos/utils/test"
)

var _ = Describe("configure_nic_test", func() {
    var cmd *configureNicCmd
    BeforeEach(func() {
        utils.InitLog(test.VYOS_UT_LOG_FOLDER + "configure_nic_test.log", false)
        SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
        cmd = &configureNicCmd{}
    })

    AfterEach(func() {
        removeNic(cmd)
        for i, _ := range cmd.Nics {
            checkNicFirewallDelete(cmd.Nics[i])
        }
    })

    It("TestConfigureNic", func() {
        cmd.Nics = append(cmd.Nics, test.PrivateNicsForUT[0])
        cmd.Nics = append(cmd.Nics, test.PrivateNicsForUT[1])
        cmd.Nics = append(cmd.Nics, test.AdditionalPubNicsForUT[0])
        log.Debugf("############### TestConfigureNic ###############")
        configureNic(cmd)
        checkNicFirewall(test.PrivateNicsForUT[0])
        checkNicFirewall(test.PrivateNicsForUT[1])
        checkNicFirewall(test.AdditionalPubNicsForUT[0])
    })

    It("TestConfigureNicFirewallDefaultAction", func() {
        cmd.Nics = append(cmd.Nics, test.PrivateNicsForUT[0])
        cmd.Nics = append(cmd.Nics, test.PrivateNicsForUT[1])
        cmd.Nics = append(cmd.Nics, test.AdditionalPubNicsForUT[0])
        log.Debugf("############### TestConfigureNicFirewallDefaultAction ###############")
        configureNic(cmd)
        checkNicFirewall(test.PrivateNicsForUT[0])
        checkNicFirewall(test.PrivateNicsForUT[1])
        checkNicFirewall(test.AdditionalPubNicsForUT[0])

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
        cmd.Nics = append(cmd.Nics, test.AdditionalPubNicsForUT[0])
        cmd.Nics = append(cmd.Nics, test.PubNicForUT)
        cmd.Nics = append(cmd.Nics, test.PrivateNicsForUT[0])
        cmd.Nics = append(cmd.Nics, test.PrivateNicsForUT[1])
        log.Debugf("############### TestChangeDefaultNic ###############")
        configureNic(cmd)

        sinfo1 = snatInfo{
            PublicNicMac:  test.AdditionalPubNicsForUT[0].Mac,
            PublicIp:      test.AdditionalPubNicsForUT[0].Ip,
            PrivateNicMac: test.PrivateNicsForUT[0].Mac,
            PrivateNicIp:  test.PrivateNicsForUT[0].Ip,
            SnatNetmask:   test.PrivateNicsForUT[0].Netmask,
        }

        sinfo2 = snatInfo{
            PublicNicMac:  test.AdditionalPubNicsForUT[0].Mac,
            PublicIp:      test.AdditionalPubNicsForUT[0].Ip,
            PrivateNicMac: test.PrivateNicsForUT[1].Mac,
            PrivateNicIp:  test.PrivateNicsForUT[1].Ip,
            SnatNetmask:   test.PrivateNicsForUT[1].Netmask,
        }

        ccmd := &ChangeDefaultNicCmd {}
        ccmd.NewNic = test.AdditionalPubNicsForUT[0]
        ccmd.Snats = []snatInfo{sinfo1, sinfo2}
        log.Debugf("############### TestChangeDefaultNic change default nic ###############")
        changeDefaultNic(ccmd)
        checkSnatRuleSet(test.AdditionalPubNicsForUT[0], test.PrivateNicsForUT[0])
        checkSnatRuleSet(test.AdditionalPubNicsForUT[0], test.PrivateNicsForUT[1])

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
        ccmd.NewNic = test.PubNicForUT
        ccmd.Snats = []snatInfo{sinfo1, sinfo2}
        log.Debugf("############### TestChangeDefaultNic change default nic again ###############")
        changeDefaultNic(ccmd)
        checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[0])
        checkSnatRuleSet(test.PubNicForUT, test.PrivateNicsForUT[1])
    })

    It("TestCheckNicIsUp", func() {
        log.Debugf("############### TestCheckNicIsUp for master ###############")
        cmd.Nics = append(cmd.Nics, test.PrivateNicsForUT[0])
        configureNic(cmd)
        err := checkNicIsUp(test.PrivateNicsForUT[0].Name, false)
        gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("nic [%s] shoud be up", test.PrivateNicsForUT[0].Name))

        removeNic(cmd)
        log.Debugf("############### TestCheckNicIsUp for backup ###############")
        SetKeepalivedStatusForUt(KeepAlivedStatus_Backup)
        configureNic(cmd)
        err = checkNicIsUp(test.PrivateNicsForUT[0].Name, false)
        gomega.Expect(err).NotTo(gomega.BeNil(), fmt.Sprintf("nic [%s] is should not up", test.PrivateNicsForUT[0].Name))
        removeNic(cmd)
    })

    It("TestAddSecondaryIpFirewall", func() {
        log.Debugf("############### TestAddSecondaryIpFirewall ###############")
        cmd := &configureNicCmd{}
        cmd.Nics = append(cmd.Nics, test.AdditionalPubNicsForUT[0])
        cmd.Nics = append(cmd.Nics, test.PubNicForUT)
        cmd.Nics = append(cmd.Nics, test.PrivateNicsForUT[0])
        cmd.Nics = append(cmd.Nics, test.PrivateNicsForUT[1])
        configureNic(cmd)

        tree := server.NewParserFromShowConfiguration().Tree
        ipPubL3, _ := test.GetFreePubL3Ip()
        addSecondaryIpFirewall(test.PubNicForUT.Name, ipPubL3, tree)
        tree.Apply(false)

        checkSecondaryIpFirewall(test.PubNicForUT, ipPubL3)
    
        test.ReleasePubL3Ip(ipPubL3)
    })
})

func checkNicFirewall(nic utils.NicInfo)  {
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

    if nic.Category == utils.NIC_TYPE_PRIVATE {
        cmd = fmt.Sprintf("firewall name %s.in rule 4000 state invalid enable", nic.Name)
        rule = tree.Get(cmd)
        gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

        cmd = fmt.Sprintf("firewall name %s.in rule 4000 state new enable", nic.Name)
        rule = tree.Get(cmd)
        gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))
    }
    
    cmd = fmt.Sprintf("firewall name %s.in rule 4000 action accept", nic.Name)
    rule = tree.Get(cmd)
    gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))
    
    cmd = fmt.Sprintf("firewall name %s.in rule 4001 protocol icmp", nic.Name)
    rule = tree.Get(cmd)
    gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

    if nic.Category == utils.NIC_TYPE_PUBLIC {
        cmd = fmt.Sprintf("firewall name %s.in rule 9999 action accept", nic.Name)
        rule = tree.Get(cmd)
        gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))

        cmd = fmt.Sprintf("firewall name %s.in rule 9999 state new enable", nic.Name)
        rule = tree.Get(cmd)
        gomega.Expect(rule).NotTo(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] check failed", cmd))
    }
}

func checkNicFirewallDelete( nic utils.NicInfo)  {
    tree := server.NewParserFromShowConfiguration().Tree
    cmd := fmt.Sprintf("firewall name %s.in", nic.Name)
    rule := tree.Get(cmd)
    gomega.Expect(rule).To(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] delete failed", cmd))

    cmd = fmt.Sprintf("firewall name %s.local", nic.Name)
    rule = tree.Get(cmd)
    gomega.Expect(rule).To(gomega.BeNil(), fmt.Sprintf("firewall rule [%s] delete failed", cmd))
}

func checkSecondaryIpFirewall(nic utils.NicInfo, ip string)  {
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

/*
func TestCheckNicIsUp(t *testing.T)  {
    cmd := &configureNicCmd{}
    cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[0])
    configureNic(cmd)
    if err := checkNicIsUp(utils.PrivateNicsForUT[0].Name, false); err == nil {
        t.Fatalf("nic [%s] shoud not be up", utils.PrivateNicsForUT[0].Name)
    }
    removeNic(cmd)
    
    keepAlivedStatus = KeepAlivedStatus_Master
    configureNic(cmd)
    if err := checkNicIsUp(utils.PrivateNicsForUT[0].Name, false); err != nil {
        t.Fatalf("nic [%s] is not up", utils.PrivateNicsForUT[0].Name)
    }
    removeNic(cmd)
    
    keepAlivedStatus = KeepAlivedStatus_Backup
}
*/
