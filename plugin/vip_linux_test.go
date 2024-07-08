package plugin

import (
	"fmt"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = XDescribe("vip_linux_test", func() {

	It("[REPLACE_VYOS]: pre test env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"vip_linux_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetEnableVyosCmdForUT(false)
		utils.SetSkipVyosIptablesForUT(true)

		configureAllNicsForUT()
	})

	It("[REPLACE_VYOS]: test set vip with no-ha", func() {
		vipInfos := []vipInfo{}
		ipForVip1, _ := utils.GetFreePubL3Ip()
		ipForVip2, _ := utils.GetFreePubL3Ip()
		vip1 := vipInfo{Ip: ipForVip1, Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vip2 := vipInfo{Ip: ipForVip2, Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vipInfos = append(vipInfos, vip1)
		vipInfos = append(vipInfos, vip2)
		ip1 := nicIpInfo{Ip: utils.PubNicForUT.Ip, Netmask: utils.PubNicForUT.Netmask, OwnerEthernetMac: utils.PubNicForUT.Mac}

		utils.SetHaStatus(utils.NOHA)
		cmd := &setVipCmd{SyncVip: false, Vips: vipInfos, NicIps: []nicIpInfo{ip1}}
		log.Debugf("setvipByLinux cmd: %+v", cmd)
		setVipByLinux(cmd)
		checkVipConfigByLinux(vipInfos, utils.PubNicForUT, utils.NOHA)

		rmCmd := &removeVipCmd{Vips: vipInfos}
		removeVipByLinux(rmCmd)
		checkVipDeleteByLinux(vipInfos, utils.PubNicForUT)

		nicCmd := &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		utils.ReleasePubL3Ip(ipForVip1)
		utils.ReleasePubL3Ip(ipForVip2)
	})

	It("[REPLACE_VYOS]: test set vip with ha-back", func() {
		nicCmd := &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)

		var vips []vipInfo
		ipForVip1, _ := utils.GetFreePubL3Ip()
		ipForVip2, _ := utils.GetFreePubL3Ip()
		vip1 := vipInfo{Ip: ipForVip1, Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vip2 := vipInfo{Ip: ipForVip2, Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vips = append(vips, vip1)
		vips = append(vips, vip2)
		ip1 := nicIpInfo{Ip: utils.PubNicForUT.Ip, Netmask: utils.PubNicForUT.Netmask, OwnerEthernetMac: utils.PubNicForUT.Mac}

		utils.SetEnableVyosCmdForUT(false)
		utils.SetHaStatus(utils.HABACKUP)
		cmd := &setVipCmd{SyncVip: false, Vips: vips, NicIps: []nicIpInfo{ip1}}
		setVipByLinux(cmd)
		checkVipConfigByLinux(vips, utils.PubNicForUT, utils.HABACKUP)

		setVipByLinux(cmd)
		checkVipConfigByLinux(vips, utils.PubNicForUT, utils.HABACKUP)

		rcmd := &removeVipCmd{Vips: vips}
		removeVipByLinux(rcmd)
		checkVipDeleteByLinux(vips, utils.PubNicForUT)

		removeVipByLinux(rcmd)
		checkVipDeleteByLinux(vips, utils.PubNicForUT)
	})

	It("[REPLACE_VYOS]: test destory env", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkVipDeleteByLinux(vips []vipInfo, nic utils.NicInfo) {
	ipLists, _ := utils.Ip4AddrShow(nic.Name)
	cidr, err := utils.NetmaskToCIDR(nic.Netmask)
	utils.PanicOnError(err)
	addr := fmt.Sprintf("%v/%v", nic.Ip, cidr)
	Expect(ipLists).To(ContainElement(addr), "nic[%s] ip[%s] should in ipList[%+v]", nic.Name, addr, ipLists)

	for _, vip := range vips {
		cidr, err := utils.NetmaskToCIDR(vip.Netmask)
		utils.PanicOnError(err)
		addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)
		ok, err := utils.IpAddrIsExist(nic.Name, addr)
		Expect(err).To(BeNil(), "IpAddrIsExist[%s, %s] error: %+v", nic.Name, addr, err)
		Expect(ok).To(BeFalse(), "vip[%s] should be delete on nic[%s]", addr, nic.Name)
	}
}

func checkVipConfigByLinux(vipInfos []vipInfo, nic utils.NicInfo, haStatus string) {
	ipLists, _ := utils.Ip4AddrShow(nic.Name)
	cidr, err := utils.NetmaskToCIDR(nic.Netmask)
	utils.PanicOnError(err)
	addr := fmt.Sprintf("%v/%v", nic.Ip, cidr)
	Expect(ipLists).To(ContainElement(addr), "nic[%s] ip[%s] should in ipList[%+v]", nic.Name, addr, ipLists)

	for _, vip := range vipInfos {
		cidr, err := utils.NetmaskToCIDR(vip.Netmask)
		utils.PanicOnError(err)
		addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)

		if haStatus != utils.HABACKUP || nic.Name != utils.MgtNicForUT.Name {
			Expect(ipLists).To(ContainElement(addr), "nic[%s] vip[%s] should in ipList[%+v]", nic.Name, nic.Ip, ipLists)
		} else {
			Expect(ipLists).NotTo(ContainElement(addr), "nic[%s] vip[%s] should in ipList[%+v]", nic.Name, nic.Ip, ipLists)
		}
	}
}
