package plugin

import (
	"fmt"
	"strings"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("vip_test", func() {
	It("vip_test prepare env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"vip_test.log", false)
		utils.CleanTestEnvForUT()
	})

	It("test set vip for no ha", func() {
		nicCmd := &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)

		var vips []vipInfo
		vip1 := vipInfo{Ip: "100.64.1.200", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vip2 := vipInfo{Ip: "100.64.1.201", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vips = append(vips, vip1)
		vips = append(vips, vip2)
		ip1 := nicIpInfo{Ip: utils.PubNicForUT.Ip, Netmask: utils.PubNicForUT.Netmask, OwnerEthernetMac: utils.PubNicForUT.Mac}

		oldHaStatus := utils.GetHaStatus()
		utils.SetHaStatus(utils.NOHA)
		cmd := &setVipCmd{SyncVip: false, Vips: vips, NicIps: []nicIpInfo{ip1}}
		log.Debugf("setvip %+v", cmd)
		setVip(cmd)
		checkVipConfig(vips, utils.PubNicForUT, utils.NOHA)

		log.Debugf("setvip %+v", cmd)
		setVip(cmd)
		checkVipConfig(vips, utils.PubNicForUT, utils.NOHA)

		rcmd := &removeVipCmd{Vips: vips}
		removeVip(rcmd)
		checkVipDelete(vips, utils.PubNicForUT)

		removeVip(rcmd)
		checkVipDelete(vips, utils.PubNicForUT)

		removeNic(nicCmd)
		utils.SetHaStatus(oldHaStatus)
	})

	It("test set vip for backup", func() {
		nicCmd := &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)

		var vips []vipInfo
		vip1 := vipInfo{Ip: "100.64.1.200", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vip2 := vipInfo{Ip: "100.64.1.201", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vips = append(vips, vip1)
		vips = append(vips, vip2)
		ip1 := nicIpInfo{Ip: utils.PubNicForUT.Ip, Netmask: utils.PubNicForUT.Netmask, OwnerEthernetMac: utils.PubNicForUT.Mac}

		oldHaStatus := utils.GetHaStatus()
		utils.SetHaStatus(utils.HABACKUP)
		cmd := &setVipCmd{SyncVip: false, Vips: vips, NicIps: []nicIpInfo{ip1}}
		setVip(cmd)
		checkVipConfig(vips, utils.PubNicForUT, utils.HABACKUP)

		setVip(cmd)
		checkVipConfig(vips, utils.PubNicForUT, utils.HABACKUP)

		rcmd := &removeVipCmd{Vips: vips}
		removeVip(rcmd)
		checkVipDelete(vips, utils.PubNicForUT)

		removeVip(rcmd)
		checkVipDelete(vips, utils.PubNicForUT)

		removeNic(nicCmd)
		utils.SetHaStatus(oldHaStatus)
	})

	It("test set vip with sync", func() {

		nicCmd := &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)

		var vips []vipInfo
		vip1 := vipInfo{Ip: "100.64.1.200", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vip2 := vipInfo{Ip: "100.64.1.201", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vips = append(vips, vip1)
		vips = append(vips, vip2)
		ip1 := nicIpInfo{Ip: utils.PubNicForUT.Ip, Netmask: utils.PubNicForUT.Netmask, OwnerEthernetMac: utils.PubNicForUT.Mac}

		oldHaStatus := utils.GetHaStatus()
		utils.SetHaStatus(utils.HABACKUP)
		cmd := &setVipCmd{SyncVip: true, Vips: vips, NicIps: []nicIpInfo{ip1}}
		setVip(cmd)
		checkVipConfig(vips, utils.PubNicForUT, utils.HABACKUP)

		// remove the nic ip address
		cidr, err := utils.NetmaskToCIDR(utils.PubNicForUT.Netmask)
		utils.PanicOnError(err)
		addr := fmt.Sprintf("%v/%v", utils.PubNicForUT.Ip, cidr)
		bash := utils.Bash{
			Command: fmt.Sprintf("ip address del %s dev %s", addr, utils.PubNicForUT.Name),
		}
		bash.Run()

		setVip(cmd)
		checkVipConfig(vips, utils.PubNicForUT, utils.HABACKUP)

		rcmd := &removeVipCmd{Vips: vips}
		removeVip(rcmd)
		checkVipDelete(vips, utils.PubNicForUT)

		removeNic(nicCmd)
		utils.SetHaStatus(oldHaStatus)
	})

	It("test set vip for backup on mgt", func() {
		nicCmd := &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.MgtNicForUT)
		oldHaStatus := utils.GetHaStatus()
		utils.SetHaStatus(utils.HABACKUP)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		log.Debugf("TestSetVipForBackupOnMgt start ##############################")
		SetKeepalivedStatusForUt(KeepAlivedStatus_Backup)

		var vips []vipInfo
		ipInMgt1, _ := utils.GetFreeMgtIp()
		ipInMgt2, _ := utils.GetFreeMgtIp()
		vip1 := vipInfo{Ip: ipInMgt1, Netmask: utils.MgtNicForUT.Netmask, Gateway: utils.MgtNicForUT.Gateway,
			OwnerEthernetMac: utils.MgtNicForUT.Mac}
		vip2 := vipInfo{Ip: ipInMgt2, Netmask: utils.MgtNicForUT.Netmask, Gateway: utils.MgtNicForUT.Gateway,
			OwnerEthernetMac: utils.MgtNicForUT.Mac}
		vips = append(vips, vip1)
		vips = append(vips, vip2)
		ip1 := nicIpInfo{Ip: utils.MgtNicForUT.Ip, Netmask: utils.MgtNicForUT.Netmask, OwnerEthernetMac: utils.MgtNicForUT.Mac}

		cmd := &setVipCmd{SyncVip: false, Vips: vips, NicIps: []nicIpInfo{ip1}}
		log.Debugf("TestSetVipForBackupOnMgt start cmd %+v", cmd)
		setVip(cmd)
		checkVipConfig(vips, utils.MgtNicForUT, utils.HABACKUP)

		log.Debugf("TestSetVipForBackupOnMgt start again cmd %+v", cmd)
		setVip(cmd)
		checkVipConfig(vips, utils.MgtNicForUT, utils.HABACKUP)

		rcmd := &removeVipCmd{Vips: vips}
		log.Debugf("TestSetVipForBackupOnMgt removeVip cmd %+v", rcmd)
		removeVip(rcmd)
		checkVipDelete(vips, utils.MgtNicForUT)

		log.Debugf("TestSetVipForBackupOnMgt removeVip cmd %+v", rcmd)
		removeVip(rcmd)
		checkVipDelete(vips, utils.MgtNicForUT)

		utils.SetHaStatus(oldHaStatus)
		utils.ReleaseMgtIp(ipInMgt1)
		utils.ReleaseMgtIp(ipInMgt2)
	})

	It("test set vip for master on mgt", func() {
		nicCmd := &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.MgtNicForUT)
		oldHaStatus := utils.GetHaStatus()
		utils.SetHaStatus(utils.HABACKUP)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		log.Debugf("TestSetVipForMasterOnMgt start ##############################")

		var vips []vipInfo
		ipInMgt1, _ := utils.GetFreeMgtIp()
		ipInMgt2, _ := utils.GetFreeMgtIp()
		vip1 := vipInfo{Ip: ipInMgt1, Netmask: utils.MgtNicForUT.Netmask, Gateway: utils.MgtNicForUT.Gateway,
			OwnerEthernetMac: utils.MgtNicForUT.Mac}
		vip2 := vipInfo{Ip: ipInMgt2, Netmask: utils.MgtNicForUT.Netmask, Gateway: utils.MgtNicForUT.Gateway,
			OwnerEthernetMac: utils.MgtNicForUT.Mac}
		vips = append(vips, vip1)
		vips = append(vips, vip2)
		ip1 := nicIpInfo{Ip: utils.MgtNicForUT.Ip, Netmask: utils.MgtNicForUT.Netmask, OwnerEthernetMac: utils.MgtNicForUT.Mac}

		cmd := &setVipCmd{SyncVip: false, Vips: vips, NicIps: []nicIpInfo{ip1}}
		log.Debugf("TestSetVipForMasterOnMgt start cmd %+v", cmd)
		setVip(cmd)
		checkVipConfig(vips, utils.MgtNicForUT, utils.HAMASTER)

		log.Debugf("TestSetVipForMasterOnMgt start again cmd %+v", cmd)
		setVip(cmd)
		checkVipConfig(vips, utils.MgtNicForUT, utils.HAMASTER)

		rcmd := &removeVipCmd{Vips: vips}
		log.Debugf("TestSetVipForMasterOnMgt removeVipCmd %+v", rcmd)
		removeVip(rcmd)
		checkVipDelete(vips, utils.MgtNicForUT)

		log.Debugf("TestSetVipForMasterOnMgt removeVipCmd %+v", rcmd)
		removeVip(rcmd)
		checkVipDelete(vips, utils.MgtNicForUT)

		utils.SetHaStatus(oldHaStatus)
		utils.ReleaseMgtIp(ipInMgt1)
		utils.ReleaseMgtIp(ipInMgt2)
	})

	It("vip_test clean env", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkVipConfig(vips []vipInfo, nic utils.NicInfo, haStatus string) {
	tree := server.NewParserFromShowConfiguration().Tree

	/* nic ip must be the first ip of the nic */
	ipsInLinux := getLinuxNicVips(nic.Name)

	gomega.Expect(ipsInLinux[0]).To(gomega.ContainSubstring(nic.Ip), "check ip[%s] in linux failed on interface %s, result %s", nic.Ip, nic.Name, ipsInLinux)

	ipMaps := make(map[string]string)
	for _, ip := range ipsInLinux {
		iip := strings.Split(ip, "/")[0]
		ipMaps[iip] = iip
	}

	for _, vip := range vips {
		cidr, err := utils.NetmaskToCIDR(vip.Netmask)
		utils.PanicOnError(err)
		addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)
		n := tree.Getf("interfaces ethernet %s address %v", nic.Name, addr)
		/* vip on mgt nic will not add to vyos, only add to linux ip command */
		if nic.Name != utils.MgtNicForUT.Name {
			gomega.Expect(n).NotTo(gomega.BeNil(), "check vip[%s] failed on interface %s", vip.Ip, nic.Name)
		} else {
			gomega.Expect(n).To(gomega.BeNil(), "check vip[%s] failed on interface %s", vip.Ip, nic.Name)
		}

		/* when vip nic is the mgt and vpc is in backip, vip will be deleted from linux */
		if haStatus != utils.HABACKUP || nic.Name != utils.MgtNicForUT.Name {
			_, ok := ipMaps[vip.Ip]
			gomega.Expect(ok).To(gomega.BeTrue(), "check ip[%s] in linux failed on interface %s, ipMaps %+v", vip.Ip, nic.Name, ipMaps)
		}
	}

	/* nic ip is still configured in vyos
	   in ut vyos, mgt nic ip is configured by dhcp
	cidr, err := utils.NetmaskToCIDR(nic.Netmask)
	utils.PanicOnError(err)
	addr := fmt.Sprintf("%v/%v", nic.Ip, cidr)

	n := tree.Getf("interfaces ethernet %s address %v", nic.Name, addr)
	gomega.Expect(n).NotTo(gomega.BeNil(), "check ip[%s] failed on interface %s", nic.Ip, nic.Name) */
}

func checkVipDelete(vips []vipInfo, nic utils.NicInfo) {
	tree := server.NewParserFromShowConfiguration().Tree

	/* nic ip must be the first ip of the nic */
	ipsInLinux := getLinuxNicVips(nic.Name)
	gomega.Expect(ipsInLinux[0]).To(gomega.ContainSubstring(nic.Ip), "check ip[%s] in linux failed on interface %s", nic.Ip, nic.Name)

	ipMaps := make(map[string]string)
	for _, ip := range ipsInLinux {
		iip := strings.Split(ip, "/")[0]
		ipMaps[ip] = iip
	}

	for _, vip := range vips {
		/* vip deleted from vyos */
		cidr, err := utils.NetmaskToCIDR(vip.Netmask)
		utils.PanicOnError(err)
		addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)
		n := tree.Getf("interfaces ethernet %s address %v", nic.Name, addr)
		gomega.Expect(n).To(gomega.BeNil(), "check vip[%s] delete failed on interface %s", vip.Ip, nic.Name)

		/* vip deleted from linux */

		_, ok := ipMaps[vip.Ip]
		gomega.Expect(ok).NotTo(gomega.BeTrue(), "check delete ip[%s] in linux failed on interface %s", vip.Ip, nic.Name)
	}

	/* nic ip is still configured in vyos in ut vyos,
	   mgt nic ip is configured by dhcp
	cidr, err := utils.NetmaskToCIDR(nic.Netmask)
	utils.PanicOnError(err)
	addr := fmt.Sprintf("%v/%v", nic.Ip, cidr)

	n := tree.Getf("interfaces ethernet %s address %v", nic.Name, addr)
	gomega.Expect(n).NotTo(gomega.BeNil(), "check ip[%s] failed on interface %s", nic.Ip, nic.Name) */
}
