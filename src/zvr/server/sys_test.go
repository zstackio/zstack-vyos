package server

import (
	"testing"
	"zvr/utils"
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
	ConfigurationSourceFunc = func() string {
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

