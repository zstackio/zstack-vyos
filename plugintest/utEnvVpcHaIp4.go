package plugintest

import (
	"os"
	"zstack-vyos/plugin"
	"zstack-vyos/utils"
)

type VpcHaIp4Env struct {
	UtEnv

	lb  plugin.LbInfo
	lb1 plugin.LbInfo

	sg  plugin.ServerGroupInfo
	sg1 plugin.ServerGroupInfo

	bs1 plugin.BackendServerInfo
	bs2 plugin.BackendServerInfo
	bs3 plugin.BackendServerInfo
	bs4 plugin.BackendServerInfo
}

func NewVpcHaIp4Env() *VpcHaIp4Env {
	utEnv := UtEnv{
		ConfigTcForVipQos: false,
		EnableVyosCmd:     false,
		SkipVyosIptables:  true,
	}
	return &VpcHaIp4Env{
		UtEnv: utEnv,
	}
}

func (env *VpcHaIp4Env) SetupVpcHaIp4BootStrap() *VpcHaIp4Env {
	utils.InitLog(utils.GetVyosUtLogDir()+"slbha.log", true)
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

	err = utils.IpLinkAdd("ut-pri", utils.IpLinkTypeVeth.String())
	priMac, _ := utils.IpLinkGetMAC("ut-pri")
	env.PriNicForUT = utils.NicInfo{
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
			"prefixLength":      64,
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
			"prefixLength":      64,
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

func (env *VpcHaIp4Env) DestroyVpcHaIp4BootStrap() {
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

func (env *VpcHaIp4Env) SetupVyosHa() {
	/* keepalived conf
	# cat zvr/keepalived/conf/keepalived.conf
	# This file is auto-generated, edit with caution!
	global_defs {
	        vrrp_garp_master_refresh 60
	        vrrp_check_unicast_src
	        script_user zstack
	    enable_script_security

	        max_auto_priority  99

	}

	vrrp_script monitor_zvr {
	       script "/home/zstack/zvr/keepalived/script/check_zvr.sh"        # cheaper than pidof
	       interval 2                      # check every 2 seconds
	       fall 2                          # require 2 failures for KO
	       rise 2                          # require 2 successes for OK
	}


	vrrp_script monitor_1.1.1.1 {
	        script "/home/zstack/zvr/keepalived/script/check_monitor_1.1.1.1.sh"
	        interval 2
	        weight -2
	        fall 3
	        rise 3
	}


	vrrp_instance vyos-ha {
	        state BACKUP
	        interface eth0
	        virtual_router_id 50
	        priority 100
	        advert_int 10
	        nopreempt

	        unicast_src_ip 172.25.116.168
	        unicast_peer {
	                172.25.116.167
	        }

	        track_script {
	                monitor_zvr

	                monitor_1.1.1.1

	        }

	        notify_master "/home/zstack/zvr/keepalived/script/notifyMaster MASTER"
	        notify_backup "/home/zstack/zvr/keepalived/script/notifyBackup BACKUP"
	        notify_fault "/home/zstack/zvr/keepalived/script/notifyBackup FAULT"
	}

	/enableVyosha
	"keepalive":10,
	"heartbeatNic":"fa:22:f8:26:65:00",
	"peerIp":"172.25.116.167",
	"localIp":"172.25.116.168",
	"monitors":["1.1.1.1"],
	"vips":[{"nicMac":"fa:e0:76:9a:2c:01","nicVip":"10.86.5.176","netmask":"255.255.255.0"},
	  {"nicMac":"fa:16:c9:1c:5a:02","nicVip":"10.1.1.200","netmask":"255.255.255.0"}
	*/
	vip4 := plugin.MacVipPair{
		NicMac:  env.PubNicForUT.Mac,
		NicVip:  "169.254.2.102",
		Netmask: "255.255.255.0",
	}
	vip6 := plugin.MacVipPair{
		NicMac:    env.PubNicForUT.Mac,
		NicVip:    "234e:0:4568::75:cf18",
		PrefixLen: 64,
	}
	vyoshacmd := &plugin.SetVyosHaCmd{
		Keepalive:    5,
		HeartbeatNic: env.PubNicForUT.Mac,
		LocalIp:      "169.254.2.100",
		PeerIp:       "169.254.2.101",
		LocalIpV6:    "234e:0:4568::19:9e8a",
		PeerIpV6:     "234e:0:4568::52:90dc",
		Monitors:     []string{},
		Vips:         []plugin.MacVipPair{vip4, vip6},
	}

	plugin.SetVyosHa(vyoshacmd)
}

func (env *VpcHaIp4Env) SetupLb() {
	plugin.InitLb()
	os.Remove(plugin.IPVS_HEALTH_CHECK_CONFIG_FILE)
	plugin.InitIpvs()

	env.lb.LbUuid = "f2c7b2ff2f834e1ea20363f49122a3b4"
	env.lb.ListenerUuid = "23fb656e4f324e74a4889582104fcbf0"
	env.lb.InstancePort = 8080
	env.lb.LoadBalancerPort = 80
	env.lb.Vip = "192.168.2.100"
	env.lb.NicIps = append(env.lb.NicIps, "192.168.3.10")
	env.lb.Mode = "udp"
	env.lb.PublicNic = env.GetNicMac("pub")
	env.lb.Parameters = append(env.lb.Parameters,
		"balancerWeight::192.168.3.10::100",
		"connectionIdleTimeout::60",
		"Nbprocess::1",
		"balancerAlgorithm::roundrobin",
		"healthCheckTimeout::2",
		"healthCheckTarget::udp:default",
		"maxConnection::2000000",
		"httpMode::http-server-close",
		"accessControlStatus::enable",
		"healthyThreshold::2",
		"healthCheckInterval::1",
		"unhealthyThreshold::2")

	env.bs1 = plugin.BackendServerInfo{
		Ip:     "192.168.3.10",
		Weight: 100,
	}

	env.bs2 = plugin.BackendServerInfo{
		Ip:     "192.168.3.11",
		Weight: 100,
	}

	env.sg = plugin.ServerGroupInfo{Name: "default-server-group",
		ServerGroupUuid: "8e52bcc526074521894162aa8db73c24",
		BackendServers:  []plugin.BackendServerInfo{env.bs1, env.bs2},
		IsDefault:       false,
	}
	env.lb.ServerGroups = []plugin.ServerGroupInfo{env.sg}
	env.lb.RedirectRules = nil

	env.lb1 = env.lb
	env.lb1.ListenerUuid = "23fb656e4f324e74a4889582104fcbf1"
	env.lb1.LoadBalancerPort = 81

	env.bs3 = plugin.BackendServerInfo{
		Ip:     "192.168.3.12",
		Weight: 100,
	}

	env.sg1 = plugin.ServerGroupInfo{Name: "server-group-1",
		ServerGroupUuid: "8e52bcc526074521894162aa8db73c25",
		BackendServers:  []plugin.BackendServerInfo{env.bs3},
		IsDefault:       false,
	}

	env.lb1.ServerGroups = []plugin.ServerGroupInfo{env.sg1}
	env.lb1.RedirectRules = nil
}

func (env *VpcHaIp4Env) DestroyLb() {
	plugin.StopIpvsHealthCheck()
}
