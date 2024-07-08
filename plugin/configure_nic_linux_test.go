package plugin

import (
	"fmt"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("configure_nic_linux_test", func() {
	var cmd *configureNicCmd
	var sinfo1, sinfo2 snatInfo

	It("[REPLACE_VYOS]: test pre env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"configure_nic_linux_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetEnableVyosCmdForUT(false)
		utils.SetSkipVyosIptablesForUT(true)
		cmd = &configureNicCmd{}
	})

	It("[REPLACE_VYOS]: test configure nic by linux", func() {
		log.Debugf("############### [REPLACE_VYOS]: test configure nic by linux ###############")
		cmd = &configureNicCmd{}
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[1])
		cmd.Nics = append(cmd.Nics, utils.AdditionalPubNicsForUT[0])
		err := configureNic(cmd)
		Expect(err).To(BeNil(), "configureNic error: %+v", err)
		checkConfiureNicByLinux(cmd)
	})
	It("[REPLACE_VYOS]: test configure nic default action by linux", func() {
		log.Debugf("####### [REPLACE_VYOS]: test configure nic default action by linux ######")
		err := configureNicDefaultActionByLinux(cmd)
		Expect(err).To(BeNil(), "configureNicDefaultActionByLinux error: %+v", err)
	})
	It("[REPLACE_VYOS]: test change default nic by linux", func() {
		log.Debugf("############### [REPLACE_VYOS]: test change default nic by linux ###############")
		cmd = &configureNicCmd{}
		cmd.Nics = append(cmd.Nics, utils.AdditionalPubNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.PubNicForUT)
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[0])
		cmd.Nics = append(cmd.Nics, utils.PrivateNicsForUT[1])
		err := configureNic(cmd)
		Expect(err).To(BeNil(), "configureNic error: %+v", err)
		checkConfiureNicByLinux(cmd)

		sinfo1 = snatInfo{
			PublicNicMac:  utils.AdditionalPubNicsForUT[0].Mac,
			PublicIp:      utils.AdditionalPubNicsForUT[0].Ip,
			PrivateNicMac: utils.PrivateNicsForUT[0].Mac,
			PrivateNicIp:  utils.PrivateNicsForUT[0].Ip,
			SnatNetmask:   utils.PrivateNicsForUT[0].Netmask,
		}

		sinfo2 = snatInfo{
			PublicNicMac:  utils.AdditionalPubNicsForUT[0].Mac,
			PublicIp:      utils.AdditionalPubNicsForUT[0].Ip,
			PrivateNicMac: utils.PrivateNicsForUT[1].Mac,
			PrivateNicIp:  utils.PrivateNicsForUT[1].Ip,
			SnatNetmask:   utils.PrivateNicsForUT[1].Netmask,
		}
		ccmd := &ChangeDefaultNicCmd{}
		ccmd.NewNic = utils.AdditionalPubNicsForUT[0]
		ccmd.Snats = []snatInfo{sinfo1, sinfo2}
		err = changeDefaultNicByLinux(ccmd)
		Expect(err).To(BeNil(), "changeDefaultNicByLinux error: %+v", err)
		checkChangeDefaultNicByLinux(utils.PubNicForUT, utils.AdditionalPubNicsForUT[0])

		rcmd := removeSnatCmd{NatInfo: []snatInfo{sinfo2, sinfo1}}
		removeSnat(&rcmd)
	})
	It("[REPLACE_VYOS]: test remove nic by linux", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkChangeDefaultNicByLinux(oldNic utils.NicInfo, newNic utils.NicInfo) {
	oldPubNic, err := utils.GetNicNameByMac(oldNic.Mac)
	utils.PanicOnError(err)
	if oldNic.Gateway != "" {
		rtEntry := utils.NewIpRoute().SetGW(oldNic.Gateway).SetDev(oldPubNic).SetTable(utils.RT_TABLES_MAIN)
		ok := utils.IpRouteIsExist(rtEntry)
		Expect(ok).To(BeFalse(), "route entry[%+v] should be delete", rtEntry)
	}
	if oldNic.Gateway6 != "" {
		rt6Entry := utils.NewIpRoute().SetGW(oldNic.Gateway6).SetDev(oldPubNic).SetTable(utils.RT_TABLES_MAIN)
		ok := utils.IpRouteIsExist(rt6Entry)
		Expect(ok).To(BeFalse(), "route entry[%+v] should be delete", rt6Entry)
	}

	pubNic, err := utils.GetNicNameByMac(newNic.Mac)
	utils.PanicOnError(err)
	if newNic.Gateway != "" {
		routeEntry := utils.NewIpRoute().SetGW(newNic.Gateway).SetDev(pubNic).SetProto(utils.RT_PROTOS_STATIC).SetTable(utils.RT_TABLES_MAIN)
		ok := utils.IpRouteIsExist(routeEntry)
		Expect(ok).To(BeTrue(), "route entry[%+v] should exist", routeEntry)
	}
	if newNic.Gateway6 != "" {
		routeEntry := utils.NewIpRoute().SetGW(newNic.Gateway).SetDev(pubNic).SetProto(utils.RT_PROTOS_STATIC).SetTable(utils.RT_TABLES_MAIN)
		ok := utils.IpRouteIsExist(routeEntry)
		Expect(ok).To(BeTrue(), "route entry[%+v] should exist", routeEntry)
	}
}

func checkConfiureNicByLinux(cmd *configureNicCmd) {
	for _, nic := range cmd.Nics {
		nicname, _ := utils.GetNicNameByMac(nic.Mac)
		if nic.Ip != "" {
			Expect(nic.Netmask).NotTo(BeEmpty(), "nic[%s] netmask should not be empty", nic.Name)
			cidr, _ := utils.NetmaskToCIDR(nic.Netmask)
			ipString := fmt.Sprintf("%v/%v", nic.Ip, cidr)
			isExist, err := utils.IpAddrIsExist(nicname, ipString)
			Expect(err).To(BeNil(), "nic[%s] ip[%s] should exist, error: %+v", nicname, ipString, err)
			Expect(isExist).To(BeTrue(), "nic[%s] ip[%s] should exist", nicname, ipString)
		}
		if nic.Ip6 != "" {
			ip6String := fmt.Sprintf("%s/%d", nic.Ip6, nic.PrefixLength)
			isExist, err := utils.IpAddrIsExist(nicname, ip6String)
			Expect(err).To(BeNil(), "nic[%s] ip6[%s] should exist, error: %+v", nicname, ip6String, err)
			Expect(isExist).To(BeTrue(), "nic[%s] ip6[%s] should exist", nicname, ip6String)
		}
		linkAttr, err := utils.IpLinkShowAttrs(nicname)
		Expect(err).To(BeNil(), "get nic[%s] attr error: %+v", nicname, err)
		Expect(linkAttr).ToNot(BeNil(), "nic[%s] linkAttr should not be nil", nicname)
		Expect(linkAttr.MAC).To(Equal(nic.Mac), "Mac %s should equal %s", linkAttr.MAC, nic.Mac)
		if nic.Mtu != 0 {
			Expect(linkAttr.MTU).To(Equal(nic.Mtu), "mtu %d should equal %d", linkAttr.MTU, nic.Mtu)
		} else {
			Expect(linkAttr.MTU).To(Equal(1500), "mtu %d should equal 1500", linkAttr.MTU)
		}
		if nic.L2Type != "" {
			Expect(linkAttr.Alias).To(Equal(utils.MakeIfaceAlias(&nic)), "alias not equal")
		}
		if !IsMaster() {
			Expect(linkAttr.State).To(Equal("down"), "nic[%s] should be down", nicname)
		} else {
			Expect(linkAttr.State).To(Equal("up"), "nic[%s] should be up", nicname)
		}
	}
}
