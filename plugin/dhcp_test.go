package plugin

import (
	"fmt"
	"io/ioutil"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

var _ = Describe("dhcp_test", func() {

	It("dhcp test preparing", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"dhcp_test.log", false)
		utils.CleanTestEnvForUT()
	})

	It("test add dhcp", func() {
		cmd := &addDhcpCmd{}

		dhcpInfo := &dhcpInfo{}

		dhcpInfo.Ip = "10.0.98.186"
		dhcpInfo.Dns = []string{"10.0.98.1"}
		dhcpInfo.Mac = "fa:a6:40:d8:c2:00"
		dhcpInfo.Netmask = "255.255.255.0"
		dhcpInfo.Gateway = "10.0.98.1"
		dhcpInfo.Hostname = "10-0-98-186"
		dhcpInfo.VrNicMac = "fa:bb:d2:8e:5c:02"
		dhcpInfo.IsDefaultL3Network = true
		dhcpInfo.Mtu = 1450
		cmd.Rebuild = false

		addDhcp(cmd)

		checkDhcpScript()
	})

	It("test start dhcp", func() {
		nicCmd := &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)

		cmd := &dhcpServerCmd{}

		dhcpServer1 := &dhcpServer{}
		dhcpInfo1 := &dhcpInfo{}

		dhcpServer1.NicMac = utils.PubNicForUT.Mac
		//? dhcpServer.Subnet = "255.255.255.0"
		dhcpServer1.Mtu = 1450
		dhcpServer1.Gateway = "178.25.0.1"
		dhcpServer1.Netmask = "255.255.255.0"
		dhcpServer1.DnsDomain = "223.5.5.5"

		dhcpInfo1.Ip = "10.0.98.186"
		dhcpInfo1.Dns = []string{"10.0.98.1"}
		dhcpInfo1.Mac = utils.PubNicForUT.Mac
		dhcpInfo1.Netmask = "255.255.255.0"
		dhcpInfo1.Gateway = "10.0.98.1"
		dhcpInfo1.Hostname = "10-0-98-186"
		dhcpInfo1.VrNicMac = "fa:bb:d2:8e:5c:02"
		dhcpInfo1.IsDefaultL3Network = true
		dhcpInfo1.Mtu = 1450
		dhcpServer1.DhcpInfos = []dhcpInfo{*dhcpInfo1}

		cmd.DhcpServers = []dhcpServer{*dhcpServer1}

		nicname, err := utils.GetNicNameByMac(utils.PubNicForUT.Mac)
		utils.PanicOnError(err)
		pidFile, _, _, _ := getDhcpServerPath(nicname)
		stopDhcpServer(pidFile)
		startDhcpServer(*dhcpServer1)

		checkDhcpProcess()
	})

	It("dhcp test destroying", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkDhcpProcess() interface{} {
	bash := utils.Bash{
		Command: fmt.Sprintf("ps -ef|grep dhcp|grep -v grep"),
	}

	code, _, _, _ := bash.RunWithReturn()

	if code == 0 {
		return true
	} else {
		return false
	}
}

func checkDhcpScript() interface{} {
	_, err := ioutil.ReadFile(DHCP_DHCP_SCRIPT)
	gomega.Expect(err).To(gomega.BeNil(), "read Dhcp dhcp script failed")
	return nil
}
