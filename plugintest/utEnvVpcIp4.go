package plugintest

import (
	"os"
	"zstack-vyos/plugin"
	"zstack-vyos/utils"
)

/*
	example

# cat zvr/bootstrap-info.json

	{
	    "ConfigTcForVipQos": true,
	    "EnableVyosCmd": true,
	    "abnormalFileMaxSize": 100,
	    "additionalNics": [
	        {
	            "addressMode": "Stateful-DHCP",
	            "category": "Private",
	            "deviceName": "eth1",
	            "gateway": "192.69.123.1",
	            "gateway6": "2345:0:4567::1",
	            "ip": "192.69.123.1",
	            "ip6": "2345:0:4567::1",
	            "isDefaultRoute": false,
	            "l2type": "L2VlanNetwork",
	            "mac": "fa:dc:41:9d:98:01",
	            "mtu": 1500,
	            "netmask": "255.255.255.0",
	            "physicalInterface": "zsn1",
	            "prefixLength": 64,
	            "vni": 655
	        },
	        {
	            "addressMode": "Stateful-DHCP",
	            "category": "Private",
	            "deviceName": "eth2",
	            "gateway6": "234e:0:4569::1",
	            "ip6": "234e:0:4569::1",
	            "isDefaultRoute": false,
	            "l2type": "L2VlanNetwork",
	            "mac": "fa:d6:f3:1f:88:02",
	            "mtu": 1500,
	            "physicalInterface": "zsn0",
	            "prefixLength": 64,
	            "vni": 2233
	        },
	        {
	            "category": "Private",
	            "deviceName": "eth3",
	            "gateway": "192.167.100.1",
	            "ip": "192.167.100.1",
	            "isDefaultRoute": false,
	            "l2type": "L2VlanNetwork",
	            "mac": "fa:cf:11:6c:91:03",
	            "mtu": 1500,
	            "netmask": "255.255.255.0",
	            "physicalInterface": "enp23s0f1",
	            "vni": 894
	        }
	    ],
	    "applianceVmSubType": "vpcvrouter",
	    "haStatus": "NoHa",
	    "managementNic": {
	        "category": "Public",
	        "deviceName": "eth0",
	        "gateway": "172.25.0.1",
	        "ip": "172.25.116.75",
	        "isDefaultRoute": true,
	        "l2type": "L2VlanNetwork",
	        "mac": "fa:b9:6a:a7:41:00",
	        "mtu": 1500,
	        "netmask": "255.255.0.0",
	        "physicalInterface": "zsn0",
	        "vni": 31
	    },
	    "managementNodeCidr": "172.25.0.0/16",
	    "managementNodeIp": "172.25.17.40",
	    "publicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDqvnsoux4EBADU/EM1RaMTz1hCPd4bdMIAe91rto417Uad/CF80FNGPFG1NtL241feo0kdel2Y6wjob5/Xhm0V09ucM5+SQzRLXXJf3W80PvSaj63Tra0Tki0ZdjGXmjOekUwP7dnIwM+ME2DGheI6YeGzqBb7dxIvzsb3xDu/GSdcGGGEpLgKi96f1FZ987ok06DR0CeDCcgBiNBEO/H5nuar6FY+ar0K6LPtXidJWAacvHaYPSDaie9JuaXKc5xk2CEtSgw4iLY/yU+zIQFKxkjhBa0qZoMbF7xyxRVlfElYR3x8MJCWL6HyAWsV9o9lfEBlzzWR3cGCXUckV0suDD2oQ5Ukzh97NsLVFaH7L2bhsxggrmnh1aM/bdrRrVmPdjuEKWkM2gJHcdQI52X5pNyxjcOb242Azfw8P10yR3LwhVeHpgmorz06Ec9nIs4o+me6Xg6t8DOhI9oSkcyVyV2dHgxPYG3SMWA5tik1CzBUwUlj6UoXlPKLv+/5Ro8= root@172-25-17-40",
	    "sshPort": 22,
	    "uuid": "b8c63033c66d43ac9e4ce930b280d195",
	    "vyosPassword": "vrouter12#"
	}
*/
type VpcIp4Env struct {
	UtEnv

	ipsec1 plugin.IpsecInfo

	snat1, snat2, snat3, snat4 plugin.SnatInfo
	setSnatState               plugin.SetSnatStateCmd
}

func NewVpcIpv4Env() *VpcIp4Env {
	utEnv := UtEnv{
		ConfigTcForVipQos: false,
		EnableVyosCmd:     false,
		SkipVyosIptables:  true,
	}

	return &VpcIp4Env{
		UtEnv: utEnv,
	}
}

func (env *VpcIp4Env) SetupBootStrap() *VpcIp4Env {
	utils.InitLog(utils.GetVyosUtLogDir()+"vpc.log", true)
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
		Ip:                    "10.1.1.100",
		Netmask:               "255.255.255.0",
		Gateway:               "10.1.1.1",
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
		Ip:                    "10.2.1.1",
		Netmask:               "255.255.255.0",
		Gateway:               "10.2.1.1",
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

	err = utils.IpLinkAdd("ut-pub1", utils.IpLinkTypeVeth.String())
	utils.PanicOnError(err)
	pubMac1, _ := utils.IpLinkGetMAC("ut-pub1")
	env.additionalPubNicForUT1 = utils.NicInfo{
		Ip:                    "10.1.2.100",
		Netmask:               "255.255.255.0",
		Gateway:               "10.1.2.1",
		Mac:                   pubMac1,
		Category:              "Public",
		L2Type:                "L2NoVlanNetwork",
		PhysicalInterface:     "ens3",
		Vni:                   0,
		FirewallDefaultAction: "drop",
		Mtu:                   1400,
		Name:                  "ut-pub1",
		IsDefault:             false,
	}

	err = utils.IpLinkAdd("ut-pub2", utils.IpLinkTypeVeth.String())
	utils.PanicOnError(err)
	pubMac2, _ := utils.IpLinkGetMAC("ut-pub2")
	env.additionalPubNicForUT2 = utils.NicInfo{
		Ip:                    "10.1.3.100",
		Netmask:               "255.255.255.0",
		Gateway:               "10.1.3.1",
		Mac:                   pubMac2,
		Category:              "Public",
		L2Type:                "L2NoVlanNetwork",
		PhysicalInterface:     "ens3",
		Vni:                   0,
		FirewallDefaultAction: "drop",
		Mtu:                   1400,
		Name:                  "ut-pub2",
		IsDefault:             false,
	}

	err = utils.IpLinkAdd("ut-pri1", utils.IpLinkTypeVeth.String())
	priMac1, _ := utils.IpLinkGetMAC("ut-pri1")
	env.PriNicForUT1 = utils.NicInfo{
		Ip:                    "10.2.2.1",
		Netmask:               "255.255.255.0",
		Gateway:               "10.2.2.1",
		Mac:                   priMac1,
		Category:              "priMac1",
		L2Type:                "L2NoVlanNetwork",
		PhysicalInterface:     "ens3",
		Vni:                   0,
		FirewallDefaultAction: "drop",
		Mtu:                   1400,
		Name:                  "ut-pri1",
		IsDefault:             false,
	}

	utils.PrivateNicsForUT = append(utils.PrivateNicsForUT, env.PriNicForUT)

	utils.BootstrapInfo["ConfigTcForVipQos"] = true
	utils.BootstrapInfo["EnableVyosCmd"] = true
	utils.BootstrapInfo["SkipVyosIptables"] = false
	utils.BootstrapInfo["abnormalFileMaxSize"] = 100
	utils.BootstrapInfo["applianceVmSubType"] = utils.APPLIANCETYPE_VPC
	utils.BootstrapInfo["haStatus"] = "NoHa"
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

	nicCmd = &plugin.ConfigureNicCmd{
		Nics: []utils.NicInfo{env.additionalPubNicForUT1},
	}
	plugin.ConfigureNic(nicCmd)

	nicCmd = &plugin.ConfigureNicCmd{
		Nics: []utils.NicInfo{env.additionalPubNicForUT2},
	}
	plugin.ConfigureNic(nicCmd)

	nicCmd = &plugin.ConfigureNicCmd{
		Nics: []utils.NicInfo{env.PriNicForUT1},
	}
	plugin.ConfigureNic(nicCmd)

	env.envCreated = true
	return env
}

func (env *VpcIp4Env) DestroyBootStrap() {
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

/*
func (env *SlbHaIp4Env) SetupVpcLb() {
	plugin.InitLb()
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

func (env *SlbHaIp4Env) DestroyVpcLb() {
	plugin.StopIpvsHealthCheck()
}
*/

func (env *VpcIp4Env) SetupIpsec() {
	if utils.IsEuler2203() {
		b := &utils.Bash{
			Command: "systemctl restart strongswan",
			Sudo:    true,
		}
		err := b.Run()
		utils.PanicOnError(err)
	}

	plugin.IPsecEntryPoint()
	err := plugin.IpsecInit()
	utils.PanicOnError(err)
	env.ipsec1.Uuid = "a6c89c57c0684cb4926b346b68eaee3a"
	env.ipsec1.PublicNic = env.PriNicForUT.Mac
	env.ipsec1.Vip = "192.168.2.101"
	env.ipsec1.LocalCidrs = []string{"192.167.100.0/24"}
	env.ipsec1.PeerAddress = "192.168.2.102"
	env.ipsec1.PeerCidrs = []string{"192.168.1.0/24"}
	env.ipsec1.IdType = "ip"

	env.ipsec1.AuthMode = "psk"
	env.ipsec1.AuthKey = "123456"

	env.ipsec1.IkeVersion = "ikev2"
	env.ipsec1.IkeLifeTime = 86400
	env.ipsec1.LifeTime = 3600
	env.ipsec1.IkeAuthAlgorithm = "sha256"
	env.ipsec1.IkeEncryptionAlgorithm = "aes256"
	env.ipsec1.IkeDhGroup = 2
	env.ipsec1.PolicyAuthAlgorithm = "sha256"
	env.ipsec1.PolicyEncryptionAlgorithm = "aes256"
	env.ipsec1.Pfs = "dh-group14"
	env.ipsec1.PolicyMode = "tunnel"
	env.ipsec1.TransformProtocol = "esp"

	env.ipsec1.ExcludeSnat = true

}

func (env *VpcIp4Env) DestroyIpsec() {
	if utils.IsEuler2203() {
		b := &utils.Bash{
			Command: "systemctl stop strongswan",
			Sudo:    true,
		}
		err := b.Run()
		utils.PanicOnError(err)

		os.ReadDir(plugin.SwanConnectionConfPath)
	}
}

func (env *VpcIp4Env) SetupSnat() {
	env.setSnatState.Enable = true

	env.snat1 = plugin.SnatInfo{
		PublicNicMac:     env.PubNicForUT.Mac,
		PublicIp:         env.PubNicForUT.Ip,
		PrivateNicMac:    env.PriNicForUT.Mac,
		PrivateNicIp:     env.PriNicForUT.Ip,
		PrivateGatewayIp: env.PriNicForUT.Gateway,
		SnatNetmask:      env.PriNicForUT.Netmask,
		State:            true,
	}

	env.snat2 = plugin.SnatInfo{
		PublicNicMac:     env.PubNicForUT.Mac,
		PublicIp:         env.PubNicForUT.Ip,
		PrivateNicMac:    env.PriNicForUT1.Mac,
		PrivateNicIp:     env.PriNicForUT1.Ip,
		PrivateGatewayIp: env.PriNicForUT1.Gateway,
		SnatNetmask:      env.PriNicForUT1.Netmask,
		State:            true,
	}

	env.snat3 = plugin.SnatInfo{
		PublicNicMac:     env.additionalPubNicForUT1.Mac,
		PublicIp:         env.additionalPubNicForUT1.Ip,
		PrivateNicMac:    env.PriNicForUT.Mac,
		PrivateNicIp:     env.PriNicForUT.Ip,
		PrivateGatewayIp: env.PriNicForUT.Gateway,
		SnatNetmask:      env.PriNicForUT.Netmask,
		State:            true,
	}

	env.snat4 = plugin.SnatInfo{
		PublicNicMac:     env.additionalPubNicForUT1.Mac,
		PublicIp:         env.additionalPubNicForUT1.Ip,
		PrivateNicMac:    env.PriNicForUT1.Mac,
		PrivateNicIp:     env.PriNicForUT1.Ip,
		PrivateGatewayIp: env.PriNicForUT1.Gateway,
		SnatNetmask:      env.PriNicForUT1.Netmask,
		State:            true,
	}
}
