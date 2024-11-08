package utils

import (
	log "github.com/sirupsen/logrus"
	"sync"
)

var slbHaCreated bool
var slbHaLock sync.Mutex

func SetupSlbHaBootStrap() (NicInfo, NicInfo, NicInfo) {
	slbHaLock.Lock()
	defer slbHaLock.Unlock()
	if slbHaCreated {
		log.Debugf("slbHaCreated is true")
		return MgtNicForUT, PubNicForUT, PriNicForUT
	}

	err := IpLinkAdd("ut-mgt", IpLinkTypeVeth.String())
	PanicOnError(err)
	mgtMac, _ := IpLinkGetMAC("ut-mgt")
	MgtNicForUT = NicInfo{
		Ip:                    "192.168.1.100",
		Netmask:               "255.255.255.0",
		Gateway:               "192.168.1.1",
		Mac:                   mgtMac,
		Category:              "Public",
		L2Type:                "L2NoVlanNetwork",
		PhysicalInterface:     "ens3",
		Vni:                   0,
		FirewallDefaultAction: "drop",
		Mtu:                   1400,
		Name:                  "ut-mgt",
		IsDefault:             false,
	}

	IpLinkAdd("ut-pub", IpLinkTypeVeth.String())
	PanicOnError(err)
	pubMac, _ := IpLinkGetMAC("ut-pub")
	PubNicForUT = NicInfo{
		Ip:                    "192.168.2.100",
		Netmask:               "255.255.255.0",
		Gateway:               "192.168.2.1",
		Mac:                   pubMac,
		Category:              "Public",
		L2Type:                "L2NoVlanNetwork",
		PhysicalInterface:     "ens3",
		Vni:                   0,
		FirewallDefaultAction: "drop",
		Mtu:                   1400,
		Name:                  "ut-pub",
		IsDefault:             false,
	}

	IpLinkAdd("ut-pri", IpLinkTypeVeth.String())
	priMac, _ := IpLinkGetMAC("ut-pri")
	PriNicForUT = NicInfo{
		Ip:                    "192.168.3.1",
		Netmask:               "255.255.255.0",
		Gateway:               "192.168.3.1",
		Mac:                   priMac,
		Category:              "Priviate",
		L2Type:                "L2NoVlanNetwork",
		PhysicalInterface:     "ens3",
		Vni:                   0,
		FirewallDefaultAction: "drop",
		Mtu:                   1400,
		Name:                  "ut-pri",
		IsDefault:             false,
	}

	BootstrapInfo["ConfigTcForVipQos"] = false
	BootstrapInfo["EnableVyosCmd"] = false
	BootstrapInfo["SkipVyosIptables"] = true
	BootstrapInfo["abnormalFileMaxSize"] = 100
	BootstrapInfo["applianceVmSubType"] = APPLIANCETYPE_SLB
	BootstrapInfo["haStatus"] = "Backup"
	BootstrapInfo["managementNodeCidr"] = "172.25.0.0/16"
	BootstrapInfo["managementNodeIp"] = "172.25.116.181"
	BootstrapInfo["publicKey"] = ""
	BootstrapInfo["sshPort"] = 22
	BootstrapInfo["uuid"] = "17cee50d5c25466b8b442fab95c2d1ac"
	BootstrapInfo["vyosPassword"] = "vrouter12#"
	BootstrapInfo["managementNic"] = map[string]interface{}{
		"category":          "Public",
		"deviceName":        MgtNicForUT.Name,
		"gateway":           MgtNicForUT.Gateway,
		"ip":                MgtNicForUT.Ip,
		"isDefaultRoute":    false,
		"l2type":            "L2NoVlanNetwork",
		"mac":               MgtNicForUT.Mac,
		"mtu":               1400,
		"netmask":           MgtNicForUT.Netmask,
		"physicalInterface": "ens3",
		"vni":               0,
	}
	BootstrapInfo["additionalNics"] = []map[string]interface{}{
		{
			"addressMode":       "Stateful-DHCP",
			"category":          "Public",
			"deviceName":        PubNicForUT.Name,
			"gateway":           PubNicForUT.Gateway,
			"gateway6":          PubNicForUT.Gateway6,
			"ip":                PubNicForUT.Ip,
			"ip6":               PubNicForUT.Ip6,
			"isDefaultRoute":    true,
			"l2type":            "L2NoVlanNetwork",
			"mac":               PubNicForUT.Mac,
			"mtu":               1400,
			"netmask":           PubNicForUT.Netmask,
			"physicalInterface": "ens4",
			"prefixLength":      64,
			"vni":               0,
		},
		{
			"addressMode":       "Stateful-DHCP",
			"category":          "Private",
			"deviceName":        PriNicForUT.Name,
			"gateway":           PriNicForUT.Gateway,
			"gateway6":          PriNicForUT.Gateway6,
			"ip":                PriNicForUT.Ip,
			"ip6":               PriNicForUT.Ip6,
			"isDefaultRoute":    false,
			"l2type":            "VxlanNetwork",
			"mac":               PriNicForUT.Mac,
			"mtu":               1400,
			"netmask":           PriNicForUT.Netmask,
			"physicalInterface": "",
			"prefixLength":      64,
			"vni":               11,
		},
	}

	slbHaCreated = true
	PrivateNicsForUT = append(PrivateNicsForUT, PriNicForUT)
	return MgtNicForUT, PubNicForUT, PriNicForUT
}

func DestroySlbHaBootStrap() {
	slbHaLock.Lock()
	defer slbHaLock.Unlock()

	IpLinkDel("ut-mgt")
	IpLinkDel("ut-pub")
	IpLinkDel("ut-pri")

	slbHaCreated = false
	log.Debugf("slbHaCreated is false")
}
