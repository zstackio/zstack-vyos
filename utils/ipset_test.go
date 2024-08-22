package utils

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ipset test", func() {

	It("preparing ipset", func() {
		InitLog(GetVyosUtLogDir()+"ipset-test.log", false)
	})

	It("ipset create", func() {
		ipset1 := NewIPSet("ipset1", IPSET_TYPE_HASH_NET)
		ipset1.Destroy()
		err := ipset1.Create()
		Expect(err).To(BeNil(), fmt.Sprintf("create ipset %+v", ipset1))

		err = ipset1.Create()
		Expect(err).To(BeNil(), fmt.Sprintf("create ipset %+v", ipset1))

		/*
			ipset2, err := GetCurrentIpSet()
			Expect(err).To(BeNil(), fmt.Sprintf("get current ipset %s", err))
			Expect(len(ipset2) == 1).To(BeTrue(), fmt.Sprintf("get current ipset len %d", len(ipset2)))
			Expect(ipset1.IsEqual(ipset2[0])).To(BeTrue(), fmt.Sprintf("get current ipset ipset2 %+v", ipset2))*/

		err = ipset1.Destroy()
		Expect(err).To(BeNil(), fmt.Sprintf("destroy ipset1 %+v", ipset1))

		/* can not be deleted multiple time
		err = ipset1.Destroy()
		Expect(err).To(BeNil(), fmt.Sprintf("destroy ipset1 %+v", ipset1))

		ipset3, err := GetCurrentIpSet()
		Expect(err).To(BeNil(), fmt.Sprintf("get current ipset %s", err))
		Expect(len(ipset3) == 0).To(BeTrue(), fmt.Sprintf("get current ipset len %d", len(ipset2))) */
	})

	It("ipset add", func() {
		ipset1 := NewIPSet("ipset1", IPSET_TYPE_HASH_IP)
		ipset1.Destroy()
		err := ipset1.Create()
		Expect(err).To(BeNil(), fmt.Sprintf("create ipset %+v", ipset1))

		member1 := []string{"1.1.1.1", "1.1.1.10-1.1.1.20", "1.1.2.0/24", "2.2.0.0/16", "3.0.0.0/8", "4.1.1.0/22"}
		ipset1.AddMember(member1)
		Expect(err).To(BeNil(), fmt.Sprintf("ipset: %+v add member: %s", ipset1, member1))

		member2 := []string{"1.1.1.1", "1.1.2.0/24", "2.2.0.0/16", "3.0.0.0/8", "4.1.1.0/22"}
		ipset1.AddMember(member2)
		Expect(err).To(BeNil(), fmt.Sprintf("ipset: %+v add member: %s", ipset1, member2))

		member3 := []string{"1.1.1.1", "1.1.2.0/24", "3.0.0.0/8"}
		ipset1.DeleteMember(member3)
		Expect(err).To(BeNil(), fmt.Sprintf("ipset: %+v delete member: %s", ipset1, member3))

		member4 := []string{"2.2.0.0/16", "3.0.0.0/8", "4.1.1.0/22"}
		ipset1.DeleteMember(member4)
		Expect(err).To(BeNil(), fmt.Sprintf("ipset: %+v delete member: %s", ipset1, member4))

		ipset1.Destroy()
	})

	It("multiple ipset", func() {
		ipset1 := NewIPSet("ipset1", IPSET_TYPE_HASH_NET)
		ipset1.Destroy()
		err := ipset1.Create()
		Expect(err).To(BeNil(), fmt.Sprintf("create ipset %+v", ipset1))

		member1 := []string{"1.1.1.1", "1.1.2.0/24", "2.2.0.0/16", "3.0.0.0/8", "4.1.1.0/22"}
		ipset1.AddMember(member1)
		Expect(err).To(BeNil(), fmt.Sprintf("ipset: %+v add member: %s", ipset1, member1))

		ipset2 := NewIPSet("ipset2", IPSET_TYPE_HASH_NET)
		ipset2.Destroy()
		err = ipset2.Create()
		Expect(err).To(BeNil(), fmt.Sprintf("create ipset %+v", ipset2))

		member2 := []string{"1.1.2.0/24", "3.0.0.0/8"}
		ipset2.AddMember(member2)
		Expect(err).To(BeNil(), fmt.Sprintf("ipset: %+v delete member: %s", ipset2, member2))

		ipset3 := NewIPSet("ipset3", IPSET_TYPE_HASH_NET)
		ipset3.Destroy()
		err = ipset3.Create()
		Expect(err).To(BeNil(), fmt.Sprintf("create ipset %+v", ipset3))

		member3 := []string{"1.1.2.0/24", "3.0.0.0/8", "5.5.5.5"}
		ipset3.DeleteMember(member3)
		Expect(err).To(BeNil(), fmt.Sprintf("ipset: %+v delete member: %s", ipset2, member3))

		/*
			ipsets, err := GetCurrentIpSet()
			Expect(err).To(BeNil(), fmt.Sprintf("get current ipset %s", err))
			Expect(len(ipsets) == 3).To(BeTrue(), fmt.Sprintf("get current ipset len %d", len(ipsets)))

			ex1 := false
			ex2 := false
			ex3 := false
			for _, ipset := range ipsets {
				if ipset1.IsEqual(ipset) {
					ex1 = true
					break
				}

				if ipset2.IsEqual(ipset) {
					ex2 = true
					break
				}

				if ipset3.IsEqual(ipset) {
					ex3 = true
					break
				}
			}

			Expect(ex1).To(BeTrue(), fmt.Sprintf("get current ipset1 %+v failed", *ipset1))
			Expect(ex2).To(BeTrue(), fmt.Sprintf("get current ipset2 %+v failed", *ipset2))
			Expect(ex3).To(BeTrue(), fmt.Sprintf("get current ipset3 %+v failed", *ipset3)) */

		ipset1.Destroy()
		ipset2.Destroy()
		ipset3.Destroy()
	})
	It("test ipset isExist", func() {
		ipset1 := NewIPSet("ipset1", IPSET_TYPE_HASH_NET)
		ipset1.Destroy()
		err := ipset1.Create()
		Expect(err).To(BeNil(), fmt.Sprintf("create ipset %+v", ipset1))
		isExist := ipset1.IsExist()
		Expect(isExist).To(BeTrue(), fmt.Sprintf("ipset[%+v] expect exist, but not", ipset1))
		ipset1.Destroy()
	})

	It("test ipset swap", func() {
		ipset1 := NewIPSet("ipset1", IPSET_TYPE_HASH_NET)
		ipset1.Destroy()
		ipset2 := NewIPSet("ipset2", IPSET_TYPE_HASH_NET)
		ipset2.Destroy()

		err1 := ipset1.Create()
		Expect(err1).To(BeNil(), fmt.Sprintf("create ipset %+v", ipset1))
		err2 := ipset2.Create()
		Expect(err2).To(BeNil(), fmt.Sprintf("create ipset %+v", ipset2))

		member1 := []string{"1.1.1.5", "1.1.3.0/24", "10.1.1.0/24"}
		err1 = ipset1.AddMember(member1)
		Expect(err1).To(BeNil(), fmt.Sprintf("ipset: %+v add member: %s", ipset1, member1))
		member2 := []string{"2.2.2.0/24", "10.0.0.0/8"}
		err2 = ipset2.AddMember(member2)
		Expect(err2).To(BeNil(), fmt.Sprintf("ipset: %+v delete member: %s", ipset2, member2))

		isSwap := ipset1.Swap(ipset2)
		Expect(isSwap).To(BeTrue(), fmt.Sprintf("ipset swap %+v to %+v error", ipset1, ipset2))

		ipset1.Destroy()
		ipset2.Destroy()
	})

})
