package utils

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ip_addr_test", func() {
	It("test ip[v4] addr cmd", func() {
		link := "eth1"
		address := "10.10.10.100/24"

		err := Ip4AddrFlush(link)
		Expect(err).To(BeNil(), fmt.Sprintf("ip[v4] addr flush err: %+v", err))
		err1 := IpAddrAdd(link, address)
		Expect(err1).To(BeNil(), fmt.Sprintf("ip[v4] addr add err: %+v", err1))
		isExist, _ := IpAddrIsExist(link, address)
		Expect(isExist).To(BeTrue(), fmt.Sprintf("address [%s] should exist, but not", address))
		err2 := IpAddrDel(link, address)
		Expect(err2).To(BeNil(), fmt.Sprintf("ip[v4] addr del err: %+v", err2))
		isExist1, _ := IpAddrIsExist(link, address)
		Expect(isExist1).To(BeFalse(), fmt.Sprintf("address [%s] should not exist, but not", address))
	})

	It("test ip[v6] addr cmd", func() {
		link := "eth2"
		addr6 := "2001::2/64"

		err := Ip6AddrFlush(link)
		Expect(err).To(BeNil(), fmt.Sprintf("ip[v6] addr flush err: %+v", err))
		err1 := IpAddrAdd(link, addr6)
		Expect(err1).To(BeNil(), fmt.Sprintf("ip[v6] addr add err: %+v", err1))
		isExist, _ := IpAddrIsExist(link, addr6)
		Expect(isExist).To(BeTrue(), fmt.Sprintf("address [%s] should exist, but not", addr6))
		err2 := IpAddrDel(link, addr6)
		Expect(err2).To(BeNil(), fmt.Sprintf("ip[v6] addr del err: %+v", err2))
		isExist1, _ := IpAddrIsExist(link, addr6)
		Expect(isExist1).To(BeFalse(), fmt.Sprintf("address [%s] should not exist, but not", addr6))
	})

	It("test ipv4/ipv6 cmd", func() {
		link := "eth2"
		addr4_1 := "20.20.20.20/24"
		addr4_2 := "30.30.30.30/16"
		addr6_1 := "2001::4/64"
		addr6_2 := "2001::5/64"

		err := IpAddrFlush(link)
		Expect(err).To(BeNil(), fmt.Sprintf("ip[v6] addr flush err: %+v", err))

		err1 := IpAddrAdd(link, addr4_1)
		err2 := IpAddrAdd(link, addr4_2)
		err3 := IpAddrAdd(link, addr6_1)
		err4 := IpAddrAdd(link, addr6_2)
		Expect(err1).To(BeNil(), fmt.Sprintf("ip[%s] addr add err: %+v", addr4_1, err1))
		Expect(err2).To(BeNil(), fmt.Sprintf("ip[%s] addr add err: %+v", addr4_2, err2))
		Expect(err3).To(BeNil(), fmt.Sprintf("ip[%s] addr add err: %+v", addr6_1, err3))
		Expect(err4).To(BeNil(), fmt.Sprintf("ip[%s] addr add err: %+v", addr6_2, err4))

		ipLists := []string{addr4_1, addr4_2, addr6_1, addr6_2}
		ok := checkIpLists(link, ipLists)
		Expect(ok).To(BeTrue(), "check IpAddrShow error")

		IpAddrDel(link, addr4_1)
		IpAddrDel(link, addr6_1)
		isExist1, _ := IpAddrIsExist(link, addr4_1)
		isExist2, _ := IpAddrIsExist(link, addr4_2)
		isExist3, _ := IpAddrIsExist(link, addr6_1)
		isExist4, _ := IpAddrIsExist(link, addr6_2)
		Expect(isExist1).To(BeFalse(), fmt.Sprintf("address [%s] should not exist, but not", addr4_1))
		Expect(isExist3).To(BeFalse(), fmt.Sprintf("address [%s] should not exist, but not", addr6_1))
		Expect(isExist2).To(BeTrue(), fmt.Sprintf("address [%s] should exist, but not", addr4_2))
		Expect(isExist4).To(BeTrue(), fmt.Sprintf("address [%s] should exist, but not", addr6_2))

		IpAddrDel(link, addr4_2)
		IpAddrDel(link, addr6_2)
		isExist2, _ = IpAddrIsExist(link, addr4_2)
		isExist4, _ = IpAddrIsExist(link, addr6_2)
		Expect(isExist2).To(BeFalse(), fmt.Sprintf("address [%s] should not exist, but not", addr4_2))
		Expect(isExist4).To(BeFalse(), fmt.Sprintf("address [%s] should not exist, but not", addr6_2))
	})
})

func checkIpLists(link string, ipLists []string) bool {
	targetList, err := IpAddrShow(link)
	Expect(err).To(BeNil(), fmt.Sprintf("Ip4AddrShow[%s] should return nil, but %+v", link, err))
	for _, ip := range ipLists {
		flag := false
		for _, target := range targetList {
			if target == ip {
				flag = true
				break
			}
			flag = false
		}
		if !flag {
			return false
		}
	}

	return true
}
