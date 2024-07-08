package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	_ "strings"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	_ "github.com/sirupsen/logrus"
)

var _ = Describe("zvrboot_test", func() {
	It("[REPLACE_VYOS] zvrboot: pre env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"zvrboot_test.log", false)
		utils.SetEnableVyosCmdForUT(false)
		utils.SetHaStatus(utils.HAMASTER)
	})
	It("[REPLACE_VYOS] zvrboot: test configure nic", func() {
		parseNicFromBootstrap()
		renameNic()
		checkMgmtNicConfigure()
		configureAdditionNic()
		checkAdditionNicConfigure()
	})
	It("[REPLACE_VYOS] zvrboot: test config time zone", func() {
		configureTimeZone()
		checkTimeZone()
	})
	It("[REPLACE_VYPS] zvrboot: test config password", func() {
		configurePassword()
	})
	It("[REPLACE_VYPS] zvrboot: test check ip address", func() {
		checkNicAddress()
	})
	It("[REPLACE_VYPS] zvrboot: test cconfig ssh monitor", func() {
		cleanUpCrondConfig()
		configureSshMonitor()
		checkSshMonitor()
		utils.SetEnableVyosCmdForUT(true)
	})
})

func checkSshMonitor() {
	testMap := make(utils.CronjobMap)
	err := utils.JsonLoadConfig(utils.CROND_JSON_FILE, &testMap)
	Expect(err).To(BeNil(), fmt.Sprintf("load crond json error: %+v", err))

	cronJob := testMap[1]
	Expect(cronJob).NotTo(BeNil(), "ssh monitor should exist")
	Expect(cronJob.ExecCommand).To(Equal(utils.GetCronjobFileSsh()), "ssh monitor exec command error")
	Expect(cronJob.FieldMinute).To(Equal("*/1"), "ssh monitor field error")
}

func cleanUpCrondConfig() {
	bash := utils.Bash{
		Command: fmt.Sprintf("rm -f %s/.zstack_config/cronjob", utils.GetZvrRootPath()),
		Sudo:    true,
	}
	bash.Run()
}

func checkTimeZone() {
	src, _ := ioutil.ReadFile(utils.TIME_ZONE_FILE)
	timezone := strings.ReplaceAll(string(src), "\n", "")
	Expect(timezone).To(Equal("Asia/Shanghai"), "configure time zone error")

	ok := diffConfigFile("/usr/share/zoneinfo/Asia/Shanghai", utils.LOCAL_TIME_FILE)
	Expect(ok).To(BeTrue(), "configure local time error")
}

func diffConfigFile(srcfile string, dstfile string) bool {
	var src, dst []byte
	var err error
	if src, err = ioutil.ReadFile(srcfile); err != nil {
		return false
	}
	if dst, err = ioutil.ReadFile(dstfile); err != nil {
		return false
	}

	return bytes.Equal(src, dst)
}

func checkMgmtNicConfigure() {
	//eth0 := nicsMap["eth0"]
	Expect(mgmtNic).ToNot(BeNil(), "parse eth0 configure frome BootstrapInfo error")
	if mgmtNic.Ip != "" {
		Expect(mgmtNic.Netmask).NotTo(BeEmpty(), "eth0 netmask should not be empty", mgmtNic.Name)
		cidr, _ := utils.NetmaskToCIDR(mgmtNic.Netmask)
		ipString := fmt.Sprintf("%v/%v", mgmtNic.Ip, cidr)
		isExist, err := utils.IpAddrIsExist(mgmtNic.Name, ipString)
		Expect(err).To(BeNil(), "nic[%s] ip[%s] should exist, error: %+v", mgmtNic.Name, ipString, err)
		Expect(isExist).To(BeTrue(), "nic[%s] ip[%s] should exist", mgmtNic.Name, ipString)
	}
	if mgmtNic.Ip6 != "" {
		ip6String := fmt.Sprintf("%s/%d", mgmtNic.Ip6, mgmtNic.PrefixLength)
		isExist, err := utils.IpAddrIsExist(mgmtNic.Name, ip6String)
		Expect(err).To(BeNil(), "nic[%s] ip6[%s] should exist, error: %+v", mgmtNic.Name, ip6String, err)
		Expect(isExist).To(BeTrue(), "nic[%s] ip6[%s] should exist", mgmtNic.Name, ip6String)
	}
	linkAttr, err := utils.IpLinkShowAttrs(mgmtNic.Name)
	Expect(err).To(BeNil(), "get nic[%s] attr error: %+v", mgmtNic.Name, err)
	Expect(linkAttr).ToNot(BeNil(), "nic[%s] linkAttr should not be nil", mgmtNic.Name)
	Expect(linkAttr.MAC).To(Equal(mgmtNic.Mac), "nic[%s] Mac %s should equal %s", mgmtNic.Name, linkAttr.MAC, mgmtNic.Mac)
	mgmtNodeCidr := utils.BootstrapInfo["managementNodeCidr"]
	if mgmtNodeCidr != nil {
		mgmtNodeCidrStr := mgmtNodeCidr.(string)
		nexthop, _ := utils.IpRouteGet(mgmtNodeCidrStr)
		Expect(nexthop).To(Equal(mgmtNic.Gateway), "route dst mgmt node error")
	}
}

func checkAdditionNicConfigure() {
	for _, nic := range nicsMap {
		if nic.Ip != "" {
			Expect(nic.Netmask).NotTo(BeEmpty(), "nic[%s] netmask should not be empty", nic.Name)
			cidr, _ := utils.NetmaskToCIDR(nic.Netmask)
			ipString := fmt.Sprintf("%v/%v", nic.Ip, cidr)
			isExist, err := utils.IpAddrIsExist(nic.Name, ipString)
			Expect(err).To(BeNil(), "nic[%s] ip[%s] should exist, error: %+v", nic.Name, ipString, err)
			Expect(isExist).To(BeTrue(), "nic[%s] ip[%s] should exist", nic.Name, ipString)
		}
		if nic.Ip6 != "" {
			ip6String := fmt.Sprintf("%s/%d", nic.Ip6, nic.PrefixLength)
			isExist, err := utils.IpAddrIsExist(nic.Name, ip6String)
			Expect(err).To(BeNil(), "nic[%s] ip6[%s] should exist, error: %+v", nic.Name, ip6String, err)
			Expect(isExist).To(BeTrue(), "nic[%s] ip6[%s] should exist", nic.Name, ip6String)
		}
		linkAttr, err := utils.IpLinkShowAttrs(nic.Name)
		Expect(err).To(BeNil(), "get nic[%s] attr error: %+v", nic.Name, err)
		Expect(linkAttr).ToNot(BeNil(), "nic[%s] linkAttr should not be nil", nic.Name)
		Expect(linkAttr.MAC).To(Equal(nic.Mac), "Mac %s should equal %s", linkAttr.MAC, nic.Mac)
		if nic.Mtu != 0 {
			Expect(linkAttr.MTU).To(Equal(nic.Mtu), "mtu %d should equal %d", linkAttr.MTU, nic.Mtu)
		}
		if nic.L2Type != "" {
			Expect(linkAttr.Alias).To(Equal(utils.MakeIfaceAlias(nic)), "alias not equal")
		}
	}
}
