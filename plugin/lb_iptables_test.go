package plugin

import (
	"fmt"
	"time"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("lb_iptables_test", func() {

	It("[IPTABLES]LOADBALANCER:preparing env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"lb_iptables_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
		configureAllNicsForUT()
	})

	It("[IPTABLES]LOADBALANCER:test lb will delete firewall rule after start failed", func() {
		var vips []vipInfo
		vip1 := vipInfo{Ip: "100.64.1.200", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vip2 := vipInfo{Ip: "100.64.1.201", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vips = append(vips, vip1)
		vips = append(vips, vip2)
		ip1 := nicIpInfo{Ip: utils.PubNicForUT.Ip, Netmask: utils.PubNicForUT.Netmask, OwnerEthernetMac: utils.PubNicForUT.Mac}

		cmd := &setVipCmd{SyncVip: false, Vips: vips, NicIps: []nicIpInfo{ip1}}
		setVip(cmd)

		lb := &lbInfo{}
		lb.SecurityPolicyType = "TLS_CIPHER_POLICY_1_0"
		lb.LbUuid = "f2c7b2ff2f834e1ea20363f49122a3b1"
		lb.ListenerUuid = "23fb656e4f324e74a4889582104fcbf1"
		lb.InstancePort = 433
		lb.LoadBalancerPort = 433
		lb.Vip = "100.64.1.201"
		lb.NicIps = append(lb.NicIps, "192.168.100.10")
		lb.Mode = "http"
		lb.PublicNic = utils.PubNicForUT.Mac
		lb.Parameters = append(lb.Parameters,
			"balancerWeight::192.168.100.10::100",
			"connectionIdleTimeout::60",
			"Nbprocess::1",
			"balancerAlgorithm::roundrobin",
			"healthCheckTimeout::2",
			"healthCheckTarget::tcp:default",
			"maxConnection::2000000",
			"httpMode::http-server-close",
			"accessControlStatus::disable",
			"healthyThreshold::2",
			"healthCheckInterval::5",
			"unhealthyThreshold::2")
		bs := backendServerInfo{
			Ip:     "192.168.100.10",
			Weight: 100,
		}
		sg := serverGroupInfo{Name: "default-server-group",
			ServerGroupUuid: "8e52bcc526074521894162aa8db73c24",
			BackendServers:  []backendServerInfo{bs},
			IsDefault:       false,
		}
		lb.ServerGroups = []serverGroupInfo{sg}
		lb.RedirectRules = nil

		setLb(*lb)
		checkLbIptablesRules(*lb, false)

		pid1, _ := utils.ReadPid(haproxyListeners[lb.ListenerUuid].pidPath)
		lb.NicIps = append(lb.NicIps, "192.168.100.11")
		bs2 := backendServerInfo{
			Ip:     "192.168.100.11",
			Weight: 100,
		}
		sg = serverGroupInfo{Name: "default-server-group",
			ServerGroupUuid: "8e52bcc526074521894162aa8db73c21",
			BackendServers:  []backendServerInfo{bs, bs2},
			IsDefault:       false,
		}
		lb.ServerGroups = []serverGroupInfo{sg}
		setLb(*lb)

		time.Sleep(1 * time.Second)
		pid2, _ := utils.ReadPid(haproxyListeners[lb.ListenerUuid].pidPath)
		Expect(pid2 != pid1).To(BeTrue(), "haproxy process should be changed")

		time.Sleep(1 * time.Second)
		pids3, _ := utils.ReadPid(haproxyListeners[lb.ListenerUuid].pidPath)
		Expect(pid2 == pids3).To(BeTrue(), "haproxy process should NOT change")

		delLb(*lb)
		checkLbIptablesRules(*lb, true)

		rcmd := &removeVipCmd{Vips: vips}
		removeVip(rcmd)
	})

	It("[IPTABLES]LOADBALANCER:test create udp proto loadbalancer", func() {
		var vips []vipInfo
		vip1 := vipInfo{Ip: "100.64.1.200", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vips = append(vips, vip1)
		ip1 := nicIpInfo{Ip: utils.PubNicForUT.Ip, Netmask: utils.PubNicForUT.Netmask, OwnerEthernetMac: utils.PubNicForUT.Mac}

		cmd := &setVipCmd{SyncVip: false, Vips: vips, NicIps: []nicIpInfo{ip1}}
		setVip(cmd)

		lb := &lbInfo{}
		lb.LbUuid = "b702108ea6014b65bea2faf2e5f5e311"
		lb.ListenerUuid = "7f8e9159ab5f46bd8fe64aa44248f121"
		lb.InstancePort = 21002
		lb.LoadBalancerPort = 21002
		lb.Vip = "100.64.1.200"
		lb.NicIps = append(lb.NicIps, "192.168.100.10")
		lb.Mode = "udp"
		lb.PublicNic = utils.PubNicForUT.Mac
		lb.Parameters = append(lb.Parameters,
			"balancerWeight::192.168.100.10::100",
			"healthCheckTimeout::2",
			"connectionIdleTimeout::60",
			"healthCheckTarget::udp:default",
			"maxConnection::2000000",
			"httpMode::http-server-close",
			"accessControlStatus::disable",
			"unhealthyThreshold::2",
			"healthyThreshold::2",
			"balancerAlgorithm::roundrobin",
			"healthCheckInterval::5",
			"Nbprocess::1",
			"aclEntry::")

		setLb(*lb)
		checkLbIptablesRules(*lb, false)

		delLb(*lb)
		checkLbIptablesRules(*lb, true)

		rcmd := &removeVipCmd{Vips: vips}
		removeVip(rcmd)
	})

	It("[IPTABLES]LOADBALANCER: destroying env", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkLbIptablesRules(info lbInfo, delete bool) {
	nicName, _ := utils.GetNicNameByMac(info.PublicNic)
	listener := getListener(info)

	allRules := make([]*utils.IpTableRule, 0)

	rules, _ := listener.getIptablesRule()
	allRules = append(allRules, rules...)

	priNics := utils.GetPrivteInterface()
	for _, priNic := range priNics {
		for _, r := range rules {
			newRule := r.Copy()
			newRule.SetChainName(utils.GetRuleSetName(priNic, utils.RULESET_LOCAL))
			allRules = append(allRules, newRule)
		}
	}

	rule := utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.LbRuleComment)
	rule.SetDstIp(info.Vip + "/32").SetProto(utils.IPTABLES_PROTO_ICMP)

	allRules = append(allRules, rule)

	table := utils.NewIpTables(utils.FirewallTable)
	if delete {
		for _, rule := range allRules {
			Expect(table.Check(rule)).To(BeFalse(), fmt.Sprintf("firewall not exsit, firewall still exsit firewall rule [%s] check failed", rule.String()))
		}
	} else {
		for _, rule := range allRules {
			Expect(table.Check(rule)).To(BeTrue(), fmt.Sprintf("firewall still exsit firewall rule [%s] check failed", rule.String()))
		}
	}
}
