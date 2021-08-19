package plugin

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/zstackio/zstack-vyos/utils"
)

var _ = Describe("configure_nic_perf_test", func() {
	var nicCmd configureNicCmd
	It("[PERF]CONFIGURE_NIC : prepare env", func() {
		utils.InitLog(utils.VYOS_UT_LOG_FOLDER+"configure_nic_perf_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)
	})

	Measure("[PERF]CONFIGURE_NIC : test create nic perf by ", func(b Benchmarker) {
		runtime := b.Time("runtime", func() {
			output := createAndRemoveNicPerfTest(nicCmd, 50)
			Expect(output).To(BeNil())
		})

		Ω(runtime.Seconds()).Should(BeNumerically(">", 0), "configureNic()/removeNicPerfTest() shouldn't take too short.")
	}, 1)

	It("[PERF]CONFIGURE_NIC : destroy env", func() {
		utils.SetSkipVyosIptablesForUT(false)
	})
})

func createAndRemoveNicPerfTest(nicCmd configureNicCmd, number int) interface{} {
	nicCmd = configureNicCmd{}
	nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
	for i := 1; i <= number; i++ {
		if err := configureNic(&nicCmd); err != nil {
			return err
		}
		if err := removeNic(&nicCmd); err != nil {
			return err
		}
	}

	return nil
}
