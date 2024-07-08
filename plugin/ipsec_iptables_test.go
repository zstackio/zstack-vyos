package plugin

import (
	"fmt"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("ipsec_iptables_test", func() {

	It("[IPTABLES]IPSEC : prepare", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"ipsec_iptables_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
		ipsecMap = make(map[string]ipsecInfo, IPSecInfoMaxSize)
	})

	It("[IPTABLES]IPSEC : test create ipsec", func() {
		nicCmd := &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)
		IpsecInit()
		createIPsecCmd1 := &createIPsecCmd{}
		syncIPsecCmd1 := syncIPsecCmd{}
		deleteIPsecCmd1 := deleteIPsecCmd{}

		info := ipsecInfo{}
		info.Uuid = "b7d5e47f11124661bf59905dfafe99a2"
		info.Vip = "172.24.3.157"
		info.LocalCidrs = []string{"192.169.100.0/24"}
		info.PeerAddress = "172.25.10.63"
		info.AuthKey = "1234"
		info.AuthMode = "psk"
		info.PublicNic = utils.PubNicForUT.Mac
		info.IkeAuthAlgorithm = "sha1"
		info.IkeEncryptionAlgorithm = "aes128"
		info.PolicyAuthAlgorithm = "sha1"
		info.PolicyEncryptionAlgorithm = "aes128"
		info.Pfs = "dh-group2"
		info.PolicyMode = "tunnel"
		info.TransformProtocol = "esp"
		info.PeerCidrs = []string{"172.25.10.0/24"}
		info.ExcludeSnat = true

		createIPsecCmd1.AutoRestartVpn = false
		createIPsecCmd1.Infos = []ipsecInfo{info}
		syncIPsecCmd1.AutoRestartVpn = false
		syncIPsecCmd1.Infos = []ipsecInfo{info}
		deleteIPsecCmd1.Infos = []ipsecInfo{info}

		log.Debugf("#####test create ipsec#######")
		createIPsecConnection(createIPsecCmd1)
		checkSyncIpSecRulesByIptables()

		nicInfo := nicTypeInfo{Mac: utils.PubNicForUT.Mac, NicType: "public"}
		gcmd := getConfigCmd{NicTypeInfos: []nicTypeInfo{nicInfo}}
		rsp := getFirewallConfig(&gcmd)
		grsp, _ := rsp.(getConfigRsp)
		checkFirewallRuleOfIpSec(info, nicInfo, grsp.Refs)

		log.Debugf("#####test sync ipsec#######")
		syncIPsecConnection(&syncIPsecCmd1)
		checkSyncIpSecRulesByIptables()

		log.Debugf("#####test delete ipsec#######")
		deleteIPsecConnection(&deleteIPsecCmd1)
		checkSyncIpSecRulesByIptables()

		restoreIpRuleForMainRouteTable()
	})

	//It("[IPTABLES]IPSEC : test update ipsec", func() {})  //not supported

	It("[IPTABLES]IPSEC : ipsec test destroying", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkFirewallRuleOfIpSec(ipsInfo ipsecInfo, nicInfo nicTypeInfo, refs []ethRuleSetRef) {
	for _, ref := range refs {
		if ref.Forward == "in" {
			r1 := ref.RuleSetInfo.Rules[1]
			gomega.Expect(r1.RuleNumber == 5001).To(gomega.BeTrue(),
				fmt.Sprintf("in direction ipsec rule rulenumber [%+v]", r1))
			gomega.Expect(r1.SourceIp == ipsInfo.PeerCidrs[0]).To(gomega.BeTrue(),
				fmt.Sprintf("in direction ipsec SourceIp [%+v]", r1.SourceIp))
			gomega.Expect(r1.Action == "accept").To(gomega.BeTrue(),
				fmt.Sprintf("in direction ipsec SourceIp [%+v]", r1.SourceIp))
		}
	}
}

func checkSyncIpSecRulesByIptables() {
	vipNicNameMap := make(map[string]string)
	for _, info := range ipsecMap {
		if _, ok := vipNicNameMap[info.Vip]; ok {
			continue
		}
		nicName, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)
		vipNicNameMap[info.Vip] = nicName
	}

	for _, info := range ipsecMap {
		nicName, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)

		filterTable := utils.NewIpTables(utils.FirewallTable)
		/* filter rule */
		filterRule := utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
		filterRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
		filterRule.SetProto(utils.IPTABLES_PROTO_UDP).SetDstPort("500").SetSrcIpset(ipsecAddressGroup)
		res := filterTable.Check(filterRule)
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))

		filterRule = utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
		filterRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
		filterRule.SetProto(utils.IPTABLES_PROTO_UDP).SetDstPort("4500").SetSrcIpset(ipsecAddressGroup)
		res = filterTable.Check(filterRule)
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))

		filterRule = utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
		filterRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
		filterRule.SetProto(utils.IPTABLES_PROTO_ESP).SetSrcIpset(ipsecAddressGroup)
		res = filterTable.Check(filterRule)
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))

		filterRule = utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
		filterRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
		filterRule.SetProto(utils.IPTABLES_PROTO_AH).SetSrcIpset(ipsecAddressGroup)
		res = filterTable.Check(filterRule)
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))
	}

	for _, info := range ipsecMap {
		filterTable := utils.NewIpTables(utils.FirewallTable)
		natTable := utils.NewIpTables(utils.NatTable)

		nicname, _ := vipNicNameMap[info.Vip]
		/* filter rule */
		for _, remoteCidr := range info.PeerCidrs {
			filterRule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_IN))
			filterRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
			filterRule.SetSrcIp(remoteCidr).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
			res := filterTable.Check(filterRule)
			gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))

			filterRule = utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
			filterRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
			filterRule.SetSrcIp(remoteCidr).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
			res = filterTable.Check(filterRule)
			gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", filterRule.String()))
		}

		/* nat rule */
		for _, srcCidr := range info.LocalCidrs {
			for _, remoteCidr := range info.PeerCidrs {
				natRule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
				natRule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
				natRule.SetSrcIp(srcCidr).SetDstIp(remoteCidr).SetOutNic(nicname)
				res := natTable.Check(natRule)
				gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("nat rule [%s] check failed", natRule.String()))
			}
		}
	}
}
