package plugin

import (
	"fmt"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = XDescribe("lb_perf_test", func() {
	var nicCmd configureNicCmd
	It("[PERF]LB : prepare [vyos] env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"lb_perf_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
		nicCmd = configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[1])
		nicCmd.Nics = append(nicCmd.Nics, utils.AdditionalPubNicsForUT[0])
		configureNic(&nicCmd)
	})

	Measure("[PERF]LB : test create lb perf by [vyos]", func(b Benchmarker) {
		runtime := b.Time("runtime", func() {
			output := createLbPerfTest(10)
			Expect(output).To(BeNil())
		})

		Ω(runtime.Seconds()).Should(BeNumerically(">", 0), "setLb() shouldn't take too short.")
	}, 1)

	Measure("[PERF]LB : test remove lb perf by [vyos]", func(b Benchmarker) {
		runtime := b.Time("runtime", func() {
			output := removeLbPerfTest(10)
			Expect(output).To(BeNil())
		})

		Ω(runtime.Seconds()).Should(BeNumerically(">", 0), "delLb() shouldn't take too short.")
	}, 1)

	It("[PERF]LB : destroy vyos env", func() {
		nicCmd = configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[1])
		nicCmd.Nics = append(nicCmd.Nics, utils.AdditionalPubNicsForUT[0])
		removeNic(&nicCmd)
		utils.SetSkipVyosIptablesForUT(false)
	})
})

func createLbPerfTest(number int) interface{} {
	realIp := utils.GetRandomIpForSubnet(utils.PrivateNicsForUT[0].Ip)
	for i := 1; i <= number; i++ {
		vip := vipInfo{Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac,
		}

		lb := &lbInfo{}
		lb.SecurityPolicyType = "TLS_CIPHER_POLICY_1_0"
		lb.LbUuid = fmt.Sprintf("f2c7b2ff2f834e1ea20363f49122a%03d", i)
		lb.ListenerUuid = fmt.Sprintf("23fb656e4f324e74a4889582104fc%03d", i)
		lb.InstancePort = 1000 + i
		lb.LoadBalancerPort = 2000 + i
		lb.Mode = "http"
		lb.PublicNic = utils.PubNicForUT.Mac

		if number <= 255 {
			vip.Ip = fmt.Sprintf("100.90.1.%d", i)

			lb.Vip = vip.Ip
			lb.NicIps = append(lb.NicIps, realIp)
			lb.Parameters = append(lb.Parameters,
				fmt.Sprintf("balancerWeight::192.168.100.%d::100", i),
				"connectionIdleTimeout::60",
				"Nbprocess::1",
				"balancerAlgorithm::roundrobin",
				"healthCheckTimeout::2",
				"healthCheckTarget::tcp:default",
				"maxConnection::20000",
				"httpMode::http-server-close",
				"accessControlStatus::enable",
				"healthyThreshold::2",
				"healthCheckInterval::5",
				"unhealthyThreshold::2")
		} else {
			vip.Ip = fmt.Sprintf("100.90.2.%d", i-255)

			lb.Vip = vip.Ip
			lb.NicIps = append(lb.NicIps, realIp)
			lb.Parameters = append(lb.Parameters,
				fmt.Sprintf("balancerWeight::192.168.200.%d::100", i-255),
				"connectionIdleTimeout::60",
				"Nbprocess::1",
				"balancerAlgorithm::roundrobin",
				"healthCheckTimeout::2",
				"healthCheckTarget::tcp:default",
				"maxConnection::20000",
				"httpMode::http-server-close",
				"accessControlStatus::enable",
				"healthyThreshold::2",
				"healthCheckInterval::5",
				"unhealthyThreshold::2")
		}
		vips := []vipInfo{vip}
		ip1 := nicIpInfo{Ip: utils.PubNicForUT.Ip, Netmask: utils.PubNicForUT.Netmask, OwnerEthernetMac: utils.PubNicForUT.Mac}
		cmd := &setVipCmd{SyncVip: false, Vips: vips, NicIps: []nicIpInfo{ip1}}
		setVip(cmd)
		setLb(*lb)
	}

	return nil
}

func removeLbPerfTest(number int) interface{} {
	for i := 1; i <= number; i++ {
		vip := vipInfo{Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac,
		}

		lb := &lbInfo{}
		lb.SecurityPolicyType = "TLS_CIPHER_POLICY_1_0"
		lb.LbUuid = fmt.Sprintf("f2c7b2ff2f834e1ea20363f49122a%03d", i)
		lb.ListenerUuid = fmt.Sprintf("23fb656e4f324e74a4889582104fc%03d", i)
		lb.InstancePort = 1000 + i
		lb.LoadBalancerPort = 2000 + i
		lb.Mode = "http"
		lb.PublicNic = utils.PubNicForUT.Mac

		if number <= 255 {
			vip.Ip = fmt.Sprintf("100.90.1.%d", i)

			lb.Vip = fmt.Sprintf("100.64.1.%d", i)
			lb.NicIps = append(lb.NicIps, fmt.Sprintf("192.168.100.%d", i))
			lb.Parameters = append(lb.Parameters,
				fmt.Sprintf("balancerWeight::192.168.100.%d::100", i),
				"connectionIdleTimeout::60",
				"Nbprocess::1",
				"balancerAlgorithm::roundrobin",
				"healthCheckTimeout::2",
				"healthCheckTarget::tcp:default",
				"maxConnection::20000",
				"httpMode::http-server-close",
				"accessControlStatus::enable",
				"healthyThreshold::2",
				"healthCheckInterval::5",
				"unhealthyThreshold::2")
		} else {
			vip.Ip = fmt.Sprintf("100.90.2.%d", i-255)

			lb.Vip = fmt.Sprintf("100.64.2.%d", i-255)
			lb.NicIps = append(lb.NicIps, fmt.Sprintf("192.168.200.%d", i-255))
			lb.Parameters = append(lb.Parameters,
				fmt.Sprintf("balancerWeight::192.168.200.%d::100", i-255),
				"connectionIdleTimeout::60",
				"Nbprocess::1",
				"balancerAlgorithm::roundrobin",
				"healthCheckTimeout::2",
				"healthCheckTarget::tcp:default",
				"maxConnection::20000",
				"httpMode::http-server-close",
				"accessControlStatus::enable",
				"healthyThreshold::2",
				"healthCheckInterval::5",
				"unhealthyThreshold::2")
		}
		vips := []vipInfo{vip}
		delLb(*lb)
		defer func() {
			rcmd := &removeVipCmd{Vips: vips}
			removeVip(rcmd)
		}()
	}

	return nil
}
