package plugin

import (
	"fmt"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = XDescribe("eip_perf_test", func() {
	var nicCmd configureNicCmd

	It("[PERF]EIP : prepare env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"eip_perf_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
		eipMap = make(map[string]eipInfo, EipInfoMaxSize)
		nicCmd = configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		configureNic(&nicCmd)
	})

	Measure("[PERF]EIP : test create eip perf ", func(b Benchmarker) {
		runtime := b.Time("runtime", func() {
			output := syncEipPerfTest(100)
			Expect(output).To(BeNil())
		})

		Ω(runtime.Seconds()).Should(BeNumerically(">", 0), "createEip() shouldn't take too short.")
	}, 1)

	Measure("[PERF]EIP : test remove eip perf ", func(b Benchmarker) {
		runtime := b.Time("runtime", func() {
			output := removeEipPerfTest(100)
			Expect(output).To(BeNil())
		})

		Ω(runtime.Seconds()).Should(BeNumerically(">", 0), "removeEip() shouldn't take too short.")
	}, 1)

	It("[PERF]EIP : destroy env", func() {
		nicCmd = configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		removeNic(&nicCmd)
		utils.SetSkipVyosIptablesForUT(false)
	})
})

func syncEipPerfTest(number int) interface{} {
	syncCmd := &syncEipCmd{}
	for i := 1; i <= number; i++ {
		eip := eipInfo{PublicMac: utils.PubNicForUT.Mac,
			PrivateMac:         utils.PrivateNicsForUT[0].Mac,
			SnatInboundTraffic: false,
		}
		if i <= 255 {
			eip.VipIp = fmt.Sprintf("10.10.1.%d", i)
			eip.GuestIp = fmt.Sprintf("192.168.1.%d", i)
		} else {
			eip.VipIp = fmt.Sprintf("10.10.2.%d", i-255)
			eip.GuestIp = fmt.Sprintf("192.168.2.%d", i-255)
		}

		/* For testing createEip*/
		//cmd := setEipCmd{Eip: eip}
		//err := createEip(&cmd)
		//if err != nil {
		//	return err
		//}
		syncCmd.Eips = append(syncCmd.Eips, eip)
	}

	if err := syncEip(syncCmd); err != nil {
		return err
	}

	return nil
}

func removeEipPerfTest(number int) interface{} {
	for i := 1; i <= number; i++ {
		eip := eipInfo{PublicMac: utils.PubNicForUT.Mac,
			PrivateMac:         utils.PrivateNicsForUT[0].Mac,
			SnatInboundTraffic: false,
		}
		if i <= 255 {
			eip.VipIp = fmt.Sprintf("10.10.1.%d", i)
			eip.GuestIp = fmt.Sprintf("192.168.1.%d", i)
		} else {
			eip.VipIp = fmt.Sprintf("10.10.2.%d", i-255)
			eip.GuestIp = fmt.Sprintf("192.168.2.%d", i-255)
		}
		rmCmd := &removeEipCmd{Eip: eip}
		err := removeEip(rmCmd)
		if err != nil {
			return err
		}
	}
	return nil
}
