package plugintest

import (
	"zstack-vyos/plugin"
	"zstack-vyos/utils"
)

type SlbHaIp46Env struct {
	UtEnv
}

func NewSlbHaIp46Env() *SlbHaIp46Env {
	utEnv := UtEnv{
		ConfigTcForVipQos: false,
		EnableVyosCmd:     false,
		SkipVyosIptables:  true,
	}

	return &SlbHaIp46Env{
		UtEnv: utEnv,
	}
}

func (env *SlbHaIp46Env) SetupSlbHa6BootStrap() *SlbHaIp46Env {
	utils.InitLog(utils.GetVyosUtLogDir()+"slbha6.log", true)
	utils.InitVyosVersion()

	env.envLock.Lock()
	defer env.envLock.Unlock()

	err := utils.IpLinkAdd("ut-mgt", utils.IpLinkTypeVeth.String())
	utils.PanicOnError(err)
	mgtMac, _ := utils.IpLinkGetMAC("ut-mgt")
	env.MgtNicForUT = utils.NicInfo{
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

	err = utils.IpLinkAdd("ut-pub", utils.IpLinkTypeVeth.String())
	utils.PanicOnError(err)
	pubMac, _ := utils.IpLinkGetMAC("ut-pub")
	env.PubNicForUT = utils.NicInfo{
		Ip6:                   "2024:10:25:3::43:1f50",
		PrefixLength:          64,
		Gateway6:              "2024:10:25:3::1",
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

	err = utils.IpLinkAdd("ut-pri", utils.IpLinkTypeVeth.String())
	priMac, _ := utils.IpLinkGetMAC("ut-pri")
	env.PriNicForUT = utils.NicInfo{
		Ip6:                   "2024:10:25:4::43:1fa0",
		PrefixLength:          64,
		Gateway6:              "2024:10:25:4::1",
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

	utils.PrivateNicsForUT = append(utils.PrivateNicsForUT, env.PriNicForUT)

	utils.BootstrapInfo["ConfigTcForVipQos"] = false
	utils.BootstrapInfo["EnableVyosCmd"] = false
	utils.BootstrapInfo["SkipVyosIptables"] = true
	utils.BootstrapInfo["abnormalFileMaxSize"] = 100
	utils.BootstrapInfo["applianceVmSubType"] = utils.APPLIANCETYPE_SLB
	utils.BootstrapInfo["haStatus"] = "Backup"
	utils.BootstrapInfo["managementNodeCidr"] = "172.25.0.0/16"
	utils.BootstrapInfo["managementNodeIp"] = "172.25.116.181"
	utils.BootstrapInfo["publicKey"] = ""
	utils.BootstrapInfo["sshPort"] = 22
	utils.BootstrapInfo["uuid"] = "17cee50d5c25466b8b442fab95c2d1ac"
	utils.BootstrapInfo["vyosPassword"] = "vrouter12#"
	utils.BootstrapInfo["managementNic"] = map[string]interface{}{
		"category":          "Public",
		"deviceName":        env.MgtNicForUT.Name,
		"gateway":           env.MgtNicForUT.Gateway,
		"ip":                env.MgtNicForUT.Ip,
		"isDefaultRoute":    false,
		"l2type":            "L2NoVlanNetwork",
		"mac":               env.MgtNicForUT.Mac,
		"mtu":               1400,
		"netmask":           env.MgtNicForUT.Netmask,
		"physicalInterface": "ens3",
		"vni":               0,
	}
	utils.BootstrapInfo["additionalNics"] = []map[string]interface{}{
		{
			"addressMode":       "Stateful-DHCP",
			"category":          "Public",
			"deviceName":        env.PubNicForUT.Name,
			"gateway":           env.PubNicForUT.Gateway,
			"gateway6":          env.PubNicForUT.Gateway6,
			"ip":                env.PubNicForUT.Ip,
			"ip6":               env.PubNicForUT.Ip6,
			"isDefaultRoute":    true,
			"l2type":            "L2NoVlanNetwork",
			"mac":               env.PubNicForUT.Mac,
			"mtu":               1400,
			"netmask":           env.PubNicForUT.Netmask,
			"physicalInterface": "ens4",
			"prefixLength":      env.PubNicForUT.PrefixLength,
			"vni":               0,
		},
		{
			"addressMode":       "Stateful-DHCP",
			"category":          "Private",
			"deviceName":        env.PriNicForUT.Name,
			"gateway":           env.PriNicForUT.Gateway,
			"gateway6":          env.PriNicForUT.Gateway6,
			"ip":                env.PriNicForUT.Ip,
			"ip6":               env.PriNicForUT.Ip6,
			"isDefaultRoute":    false,
			"l2type":            "VxlanNetwork",
			"mac":               env.PriNicForUT.Mac,
			"mtu":               1400,
			"netmask":           env.PriNicForUT.Netmask,
			"physicalInterface": "",
			"prefixLength":      env.PriNicForUT.PrefixLength,
			"vni":               11,
		},
	}

	nicCmd := &plugin.ConfigureNicCmd{
		Nics: []utils.NicInfo{env.MgtNicForUT},
	}
	plugin.ConfigureNic(nicCmd)

	nicCmd = &plugin.ConfigureNicCmd{
		Nics: []utils.NicInfo{env.PubNicForUT},
	}
	plugin.ConfigureNic(nicCmd)

	nicCmd = &plugin.ConfigureNicCmd{
		Nics: []utils.NicInfo{env.PriNicForUT},
	}
	plugin.ConfigureNic(nicCmd)

	env.envCreated = true
	return env
}

func (env *SlbHaIp46Env) DestroySlbHa6BootStrap() {
	env.envLock.Lock()
	defer env.envLock.Unlock()

	nicCmd := &plugin.ConfigureNicCmd{
		Nics: []utils.NicInfo{env.MgtNicForUT},
	}
	plugin.RemoveNic(nicCmd)

	nicCmd = &plugin.ConfigureNicCmd{
		Nics: []utils.NicInfo{env.PubNicForUT},
	}
	plugin.RemoveNic(nicCmd)

	nicCmd = &plugin.ConfigureNicCmd{
		Nics: []utils.NicInfo{env.PriNicForUT},
	}
	plugin.RemoveNic(nicCmd)
	utils.DestroySlbHaBootStrap()

	utils.IpLinkDel("ut-mgt")
	utils.IpLinkDel("ut-pub")
	utils.IpLinkDel("ut-pri")

	env.envCreated = false
}

func (env *SlbHaIp46Env) SetupVyosHa6() {
	/*
				# cat zvr/keepalived/conf/keepalived.conf
				# This file is auto-generated, edit with caution!
				global_defs {
				        vrrp_garp_master_refresh 60
				        vrrp_check_unicast_src
				        script_user root
				    enable_script_security

				}

				vrrp_script monitor_zvr {
				       script "/home/vyos/zvr/keepalived/script/check_zvr.sh"        # cheaper than pidof
				       interval 2                      # check every 2 seconds
				       fall 2                          # require 2 failures for KO
				       rise 2                          # require 2 successes for OK
				}



				vrrp_instance vyos-ha {
				        state BACKUP
				        interface eth1
				        virtual_router_id 50
				        priority 100
				        advert_int 10
				        nopreempt


				        unicast_src_ip 2023:12:26:1::5c:6fab
				        unicast_peer {
				                2023:12:26:1::2f:9897
				        }


				        track_script {
				                monitor_zvr

				        }
				        virtual_ipaddress {

				            2023:12:26:1::7a:bcf/64

				        }

				        notify_master "/home/vyos/zvr/keepalived/script/notifyMaster MASTER"
				        notify_backup "/home/vyos/zvr/keepalived/script/notifyBackup BACKUP"
				}

		/enableVyosha,
		"keepalive":10,
		"heartbeatNic":"fa:74:6f:7e:f3:01",
		"peerIp":"10.86.5.186",
		"peerIpV6":"2023:12:26:1::52:9df6",
		"localIp":"10.86.5.188",
		"localIpV6":"2023:12:26:1::3f:8eb7",
		"monitors":[],
		"vips":[{"nicMac":"fa:74:6f:7e:f3:01","nicVip":"10.86.5.175","netmask":"255.255.255.0"},
		{"nicMac":"fa:74:6f:7e:f3:01","nicVip":"2023:12:26:1::44:802a","prefixLen":64}
	*/
	vip6 := plugin.MacVipPair{
		NicMac:    env.PubNicForUT.Mac,
		NicVip:    "2024:10:25:3::11:18f2",
		PrefixLen: 64,
	}
	vyoshacmd := &plugin.SetVyosHaCmd{
		Keepalive:    5,
		HeartbeatNic: env.PubNicForUT.Mac,
		LocalIp:      "2024:10:25:3::43:1f50",
		PeerIp:       "2024:10:25:3::11:18f1",
		LocalIpV6:    "2024:10:25:3::43:1f50",
		PeerIpV6:     "2024:10:25:3::11:18f1",
		Monitors:     []string{},
		Vips:         []plugin.MacVipPair{vip6},
	}

	plugin.SetVyosHa(vyoshacmd)
}
