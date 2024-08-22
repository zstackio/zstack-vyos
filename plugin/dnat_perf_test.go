package plugin

import (
	"fmt"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = XDescribe("dnat_perf_test", func() {
	var nicCmd configureNicCmd

	It("[PERF]DNAT : prepare  env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"dnat_perf_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
		nicCmd = configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		configureNic(&nicCmd)
	})

	Measure("[PERF]DNAT : test set dnat perf", func(b Benchmarker) {
		runtime := b.Time("runtime", func() {
			output := setDnatPerfTest(500)
			Expect(output).To(BeNil())
		})

		Ω(runtime.Seconds()).Should(BeNumerically(">", 0), "setDnat() shouldn't take too short.")
	}, 1)

	Measure("[PERF]DNAT : test remove dnat perf ", func(b Benchmarker) {
		runtime := b.Time("runtime", func() {
			output := removeDnatPerfTest(500)
			Expect(output).To(BeNil())
		})

		Ω(runtime.Seconds()).Should(BeNumerically(">", 0), "removeDnat() shouldn't take too short.")
	}, 1)

	It("[PERF]DNAT : destroy  env", func() {
		nicCmd = configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		removeNic(&nicCmd)
		utils.SetSkipVyosIptablesForUT(false)
	})
})

func setDnatPerfTest(number int) interface{} {
	setCmd := &setDnatCmd{}

	for i := 1; i <= number; i++ {
		rule := dnatInfo{VipPortStart: 100, VipPortEnd: 65530,
			PrivatePortStart: 101, PrivatePortEnd: 65531, ProtocolType: utils.IPTABLES_PROTO_TCP,
			PublicMac: utils.PubNicForUT.Mac, PrivateMac: utils.PrivateNicsForUT[0].Mac,
			SnatInboundTraffic: false,
		}
		rule.Uuid = fmt.Sprintf("uuid%d", i)
		if i <= 255 {
			rule.VipIp = fmt.Sprintf("10.10.1.%d", i)
			rule.PrivateIp = fmt.Sprintf("192.168.1.%d", i)
			rule.AllowedCidr = fmt.Sprintf("1.1.%d.0/24", i)
		} else {
			rule.VipIp = fmt.Sprintf("10.10.2.%d", i-255)
			rule.PrivateIp = fmt.Sprintf("192.168.2.%d", i-255)
			rule.AllowedCidr = fmt.Sprintf("1.2.%d.0/24", i-255)
		}
		setCmd.Rules = append(setCmd.Rules, rule)
	}

	if err := setDnat(setCmd); err != nil {
		return err
	}

	return nil
}

func removeDnatPerfTest(number int) interface{} {
	rmCmd := &removeDnatCmd{}

	for i := 1; i <= number; i++ {
		rule := dnatInfo{VipPortStart: 100, VipPortEnd: 65530,
			PrivatePortStart: 101, PrivatePortEnd: 65531, ProtocolType: utils.IPTABLES_PROTO_TCP,
			PublicMac: utils.PubNicForUT.Mac, PrivateMac: utils.PrivateNicsForUT[0].Mac,
			SnatInboundTraffic: false,
		}
		rule.Uuid = fmt.Sprintf("uuid%d", i)
		if i <= 255 {
			rule.VipIp = fmt.Sprintf("10.10.1.%d", i)
			rule.PrivateIp = fmt.Sprintf("192.168.1.%d", i)
			rule.AllowedCidr = fmt.Sprintf("1.1.%d.0/24", i)
		} else {
			rule.VipIp = fmt.Sprintf("10.10.2.%d", i-255)
			rule.PrivateIp = fmt.Sprintf("192.168.2.%d", i-255)
			rule.AllowedCidr = fmt.Sprintf("1.2.%d.0/24", i-255)
		}
		rmCmd.Rules = append(rmCmd.Rules, rule)
	}

	if err := removeDnat(rmCmd); err != nil {
		return err
	}

	return nil
}
