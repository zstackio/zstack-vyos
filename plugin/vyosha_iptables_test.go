package plugin

import (
	"fmt"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("vyosha_iptables_test", func() {
	var (
		peerIp string
		vipIp  string
		vipIp1 string
		vip    macVipPair
		cmd    *setVyosHaCmd
		nicCmd *configureNicCmd
	)

	It("[IPTABLES]VYOSHA : vyosHa test preparing", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"vyosha_iptables_test.log", false)
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
		utils.SetSkipVyosIptablesForUT(true)
		configureNic(nicCmd)
	})

	It("[IPTABLES]VYOSHA : enable vyos", func() {
		log.Debugf("vyosHa it enable vyos")
		setVyosHa(cmd)
		checkVyosConfigByIptables(cmd)
	})

	It("[IPTABLES]VYOSHA : change vyosHa peer address", func() {
		log.Debugf("vyosHa it change vyos peer address")
		cmd.PeerIp = vipIp1
		setVyosHa(cmd)
		checkVyosConfigByIptables(cmd)
	})

	It("[IPTABLES]VYOSHA : vyosHa test destroying", func() {
		deleteKeepalived()
		utils.CleanTestEnvForUT()
	})

})

func checkVyosConfigByIptables(cmd *setVyosHaCmd) {

	heartbeatNicNme, _ := utils.GetNicNameByMac(cmd.HeartbeatNic)

	/* check vyosHa firewall */
	filterTable := utils.NewIpTables(utils.FirewallTable)
	filterRule := utils.NewIpTableRule(utils.GetRuleSetName(heartbeatNicNme, utils.RULESET_LOCAL))
	filterRule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(utils.SystemTopRule)
	filterRule.SetProto(utils.IPTABLES_PROTO_VRRP).SetSrcIp(cmd.PeerIp + "/32")
	res := filterTable.Check(filterRule)
	gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))

	filterRule = utils.NewIpTableRule(utils.GetRuleSetName(heartbeatNicNme, utils.RULESET_LOCAL))
	filterRule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(utils.SystemTopRule)
	filterRule.SetProto(utils.IPTABLES_PROTO_UDP).SetSrcIp(cmd.PeerIp + "/32").SetDstPort("3780")
	res = filterTable.Check(filterRule)
	gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))

	/* check vyosHa nat */
	natTable := utils.NewIpTables(utils.NatTable)
	natRule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
	natRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	natRule.SetProto(utils.IPTABLES_PROTO_VRRP)
	res = natTable.Check(natRule)
	gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("nat rule [%s] check failed", natRule.String()))
}

func deleteKeepalived() error {
	bash := utils.Bash{
		Command: "sudo pkill -9 keepalived",
	}
	bash.Run()

	return nil
}
func deleteMgtNicFirewall(isSkipIptables bool) error {
	if isSkipIptables {
		utils.DestroyNicFirewall(utils.MgtNicForUT.Name)
	}

	tree := server.NewParserFromShowConfiguration().Tree
	tree.DetachFirewallFromInterface(utils.MgtNicForUT.Name, "in")
	tree.DetachFirewallFromInterface(utils.MgtNicForUT.Name, "local")
	tree.Apply(false)
	tree = server.NewParserFromShowConfiguration().Tree
	tree.Deletef("firewall name %s.in", utils.MgtNicForUT.Name)
	tree.Deletef("firewall name %s.local", utils.MgtNicForUT.Name)
	tree.Apply(false)

	return nil
}
