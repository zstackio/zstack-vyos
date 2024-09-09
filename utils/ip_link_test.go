package utils

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ip_link_test", func() {
	var (
		linkName   string = "eth2"
		err        error
		linkAttrs  *IpLinkAttrs
		mac, alias string
	)

	It("test ip-link down/up", func() {
		linkAttrs, err = IpLinkShowAttrs(linkName)
		mac = linkAttrs.MAC
		alias = linkAttrs.Alias
		err := IpLinkSetUp(linkName)
		Expect(err).To(BeNil(), fmt.Sprintf("ip link set dev up error: %s", err))
		err = IpLinkSetDown(linkName)
		Expect(err).To(BeNil(), fmt.Sprintf("ip link set dev down error: %s", err))
	})
	It("test ip-link set attrs", func() {
		err = IpLinkSetMAC(linkName, "00:0c:29:7b:0a:00")
		Expect(err).To(BeNil(), fmt.Sprintf("ip link set dev mac error: %s", err))
		err = IpLinkSetMTU(linkName, 1400)
		Expect(err).To(BeNil(), fmt.Sprintf("ip link set dev mtu error: %s", err))
		err = IpLinkSetPromisc(linkName, true)
		Expect(err).To(BeNil(), fmt.Sprintf("ip link set dev promisc error: %s", err))
		err = IpLinkSetAlias(linkName, "test:alias")
		Expect(err).To(BeNil(), fmt.Sprintf("ip link set dev alias error: %s", err))
	})
	It("test ip-link show attrs", func() {
		linkAttrs, err = IpLinkShowAttrs(linkName)
		Expect(err).To(BeNil(), fmt.Sprintf("get dev attrs  error: %s", err))
		Expect(linkAttrs.Alias).To(Equal("test:alias"))
		Expect(linkAttrs.MAC).To(Equal("00:0c:29:7b:0a:00"))
		Expect(linkAttrs.MTU).To(Equal(1400))
		Expect(linkAttrs.Promisc).To(Equal(1))
	})
	It("test ip-link set name", func() {
		err = IpLinkSetName(linkName, "testName")
		Expect(err).To(BeNil(), fmt.Sprintf("ip link rename dev error: %s", err))
		linkAttrs, err = IpLinkShowAttrs("testName")
		Expect(err).To(BeNil(), fmt.Sprintf("get dev attrs  error: %s", err))
		Expect(linkAttrs.Alias).To(Equal("test:alias"))
		Expect(linkAttrs.MAC).To(Equal("00:0c:29:7b:0a:00"))

		IpLinkSetName("testName", linkName)
		IpLinkSetMAC(linkName, mac)
		IpLinkSetAlias(linkName, alias)
		IpLinkSetUp(linkName)
	})
	It("test ip-link add/del deivce", func() {
		err = IpLinkAdd("test1", IpLinkTypeIfb.String())
		Expect(err).To(BeNil(), fmt.Sprintf("ip link add device[test1] error: %s", err))
		isExist := IpLinkIsExist("test1")
		Expect(isExist).To(BeTrue(), "device[test1] should exist")
		isUp, err := IpLinkIsUp("test1")
		Expect(isUp).To(BeFalse(), "device[test1] should be down")
		_ = IpLinkSetUp("test1")
		isUp, err = IpLinkIsUp("test1")
		Expect(isUp).To(BeTrue(), "device[test1] should be up")

		err = IpLinkDel("test1")
		Expect(err).To(BeNil(), fmt.Sprintf("ip link del device[test1] error: %s", err))
		isExist = IpLinkIsExist("test1")
		Expect(isExist).To(BeFalse(), "device[test1] should be deleted")
	})
})
