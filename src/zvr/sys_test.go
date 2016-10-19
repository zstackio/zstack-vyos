package zvr

import (
	"testing"
	"zvr/utils"
	"fmt"
)

func TestFindNicNameByMac(t *testing.T) {
	text := `
interfaces {
    ethernet eth0 {
        address 172.20.14.209/16
        description main
        duplex auto
        hw-id fa:da:21:1f:1a:00
        smp_affinity auto
        speed auto
    }
    ethernet eth1 {
        hw-id fa:da:21:1f:1a:11
    }
    ethernet eth2 {
        speed auto
    }
    loopback lo {
    }
}`
	configurationSource = func() string {
		return text
	}

	name, ok := FindNicNameByMac("fa:da:21:1f:1a:00")
	utils.Assert(ok, "not found")
	utils.Assert("eth0" == name, "fa:da:21:1f:1a:00 mismatch")

	name, ok = FindNicNameByMac("fa:da:21:1f:1a:11")
	utils.Assert(ok, "not found")
	utils.Assert("eth1" == name, "fa:da:21:1f:1a:11 mismatch")

	name, ok = FindNicNameByMac("fa:da:21:1f:fa:11")
	utils.Assert(!ok, "wrong found")
}


func TestNetmaskToCIDR(t *testing.T) {
	cidr, err := NetmaskToCIDR("255.255.255.0")
	utils.Assert(cidr == 24, fmt.Sprint(cidr))
	utils.Assert(err == nil, "")

	cidr, _ = NetmaskToCIDR("255.255.252.0")
	utils.Assert(cidr == 22, fmt.Sprint(cidr))

	cidr, _ = NetmaskToCIDR("255.254.0.0")
	utils.Assert(cidr == 15, fmt.Sprint(cidr))

	cidr, _ = NetmaskToCIDR("0.0.0.0")
	utils.Assert(cidr == 0, fmt.Sprint(cidr))

	cidr, _ = NetmaskToCIDR("254.0.0.0")
	utils.Assert(cidr == 7, fmt.Sprint(cidr))

	cidr, _ = NetmaskToCIDR("255.255.255.255")
	utils.Assert(cidr == 32, fmt.Sprint(cidr))
}
