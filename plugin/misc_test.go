package plugin

import (
	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
)

var _ = Describe("misc_test", func() {
	var nicCmd *configureNicCmd

	It("prepare env ...", func() {
		utils.InitLog(utils.VYOS_UT_LOG_FOLDER+"misc_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		nicCmd = &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.MgtNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)
	})

	It("test add callback route", func() {
		ipInPubL3, _ := utils.GetFreePubL3Ip()
		defer utils.ReleasePubL3Ip(ipInPubL3)

		server.CALLBACK_IP = ipInPubL3
		addRouteIfCallbackIpChanged(true)
		gomega.Expect(utils.CheckZStackRouteExists(server.CALLBACK_IP)).To(gomega.BeTrue(),
			"failed to add the callback route for the first time.")

		utils.DeleteRouteIfExists(server.CALLBACK_IP)
		addRouteIfCallbackIpChanged(true)

		gomega.Expect(utils.CheckZStackRouteExists(server.CALLBACK_IP)).To(gomega.BeTrue(),
			"failed to add the callback route for the second time.")

		utils.DeleteRouteIfExists(server.CALLBACK_IP)
		addRouteIfCallbackIpChanged(false)
		gomega.Expect(utils.CheckZStackRouteExists(server.CALLBACK_IP)).To(gomega.BeFalse(),
			"route should not be added this time.")
	})

	It("destroy env ...", func() {
		nicCmd = &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		removeNic(nicCmd)
		deleteMgtNicFirewall(true)
	})
})
