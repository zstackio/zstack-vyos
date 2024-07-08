package plugin

import (
	"fmt"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("vyosHa_test", func() {
	var (
		peerIp string
		vipIp  string
		vipIp1 string
		vip    macVipPair
		cmd    *setVyosHaCmd
		nicCmd *configureNicCmd
	)

	It("vyosHa test preparing", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"vyosha_test.log", false)
		utils.CleanTestEnvForUT()
		peerIp, _ = utils.GetFreeMgtIp()
		vipIp, _ = utils.GetFreeMgtIp()
		vipIp1, _ = utils.GetFreeMgtIp()
		log.Debugf("vyosHa BeforeEach test peerIp: %s, vip: %s, vip1: %s", peerIp, vipIp, vipIp1)

		vip = macVipPair{NicMac: utils.MgtNicForUT.Mac, NicVip: vipIp, Netmask: utils.MgtNicForUT.Netmask}
		cmd = &setVyosHaCmd{Keepalive: 1, HeartbeatNic: utils.MgtNicForUT.Mac, LocalIp: utils.MgtNicForUT.Ip,
			PeerIp: "", Monitors: []string{"1.1.1.1", "1.1.1.2"}, Vips: []macVipPair{vip},
			CallbackUrl: "http://127.0.0.1:7272/callback"}

		nicCmd = &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.MgtNicForUT)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		configureNic(nicCmd)
	})

	It("enable vyos", func() {
		log.Debugf("vyosHa it enable vyos")
		setVyosHa(cmd)
		err := checkVyosConfig(cmd)
		Expect(err).To(BeNil(), "vyosHa check failed %+s", err)
	})

	It("change vyosHa peer address", func() {
		log.Debugf("vyosHa it change vyos peer address")
		cmd.PeerIp = vipIp1
		setVyosHa(cmd)
		err := checkVyosConfig(cmd)
		Expect(err).To(BeNil(), "vyosHa check failed %+s", err)
	})

	It("vyosHa test destroying", func() {
		utils.CleanTestEnvForUT()
	})
})

var _ = Describe("vyosHa test 2", func() {
	log.Debugf("vyosHa test Describe test 2")
})

func checkVyosConfig(vyosHa *setVyosHaCmd) error {
	tree := server.NewParserFromShowConfiguration().Tree

	des := "Vyos-HA"
	mgtNic, _ := utils.GetNicNameByMac(vyosHa.HeartbeatNic)

	/* check eip snat rule */
	rules := tree.Getf("nat source rule")
	if rules == nil {
		return fmt.Errorf("vyosHa check failed, because get nat source rule failed")
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

		cmd := fmt.Sprintf("nat source rule %s outbound-interface %s", ruleId, mgtNic)
		rule = tree.Get(cmd)
		if rule == nil {
			return fmt.Errorf("vyosHa snat rule [%s] check failed", cmd)
		}

		cmd = fmt.Sprintf("nat source rule %s protocol vrrp", ruleId)
		rule = tree.Get(cmd)
		if rule == nil {
			return fmt.Errorf("vyosHa snat rule [%s] check failed", cmd)
		}

		cmd = fmt.Sprintf("nat source rule %s exclude", ruleId)
		rule = tree.Get(cmd)
		if rule == nil {
			return fmt.Errorf("vyosHa snat rule [%s] check failed", cmd)
		}
	}

	if ruleId == "" {
		return fmt.Errorf("vyosHa [%+v] snat rule check failed", vyosHa)
	}

	/* check vyosHa firewall */
	rules = tree.Getf("firewall name %s.local rule", mgtNic)
	if rules == nil {
		return fmt.Errorf("vyosHa check failed, get: [firewall name %s.local rule] failed", mgtNic)
	}
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

		cmd := fmt.Sprintf("firewall name %s.local rule %s action accept", mgtNic, ruleId)
		rule = tree.Get(cmd)
		if rule == nil {
			return fmt.Errorf("vyosHa rule [%s] check failed", cmd)
		}

		cmd = fmt.Sprintf("firewall name %s.local rule %s source address %s", mgtNic, ruleId, vyosHa.PeerIp)
		rule = tree.Get(cmd)
		if rule == nil {
			return fmt.Errorf("vyosHa rule [%s] check failed", cmd)
		}

		cmd = fmt.Sprintf("firewall name %s.local rule %s protocol vrrp", mgtNic, ruleId)
		rule = tree.Get(cmd)
		if rule == nil {
			return fmt.Errorf("vyosHa rule [%s] check failed", cmd)
		}
	}

	if ruleId == "" {
		return fmt.Errorf("vyosHa [%+v] public firewall rule check failed", vyosHa)
	}

	return nil
}
