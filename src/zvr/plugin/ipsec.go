package plugin

import (
	"zvr/server"
	"zvr/utils"
	"fmt"
)

const(
	CREATE_IPSEC_CONNECTION = "/vyos/createipsecconnection"
	DELETE_IPSEC_CONNECTION = "/vyos/deleteipsecconnection"
	SYNC_IPSEC_CONNECTION = "/vyos/syncipsecconnection"
)

type ipsecInfo struct {
	Uuid string `json:"uuid"`
	LocalCidrs []string `json:"localCidrs"`
	PeerAddress string `json:"peerAddress"`
	AuthMode string `json:"authMode"`
	AuthKey string `json:"authKey"`
	Vip string `json:"vip"`
	IkeAuthAlgorithm string `json:"ikeAuthAlgorithm"`
	IkeEncryptionAlgorithm string `json:"ikeEncryptionAlgorithm"`
	IkeDhGroup int `json:"ikeDhGroup"`
	PolicyAuthAlgorithm string `json:"policyAuthAlgorithm"`
	PolicyEncryptionAlgorithm string `json:"policyEncryptionAlgorithm"`
	Pfs string `json:"pfs"`
	PolicyMode string `json:"policyMode"`
	TransformProtocol string `json:"transformProtocol"`
	PeerCidrs []string `json:"peerCidrs"`
	ExcludeSnat bool `json:"excludeSnat"`
}

type createIPsecCmd struct {
	Infos []ipsecInfo `json:"infos"`
}

type deleteIPsecCmd struct {
	Infos []ipsecInfo `json:"infos"`
}

type syncIPsecCmd struct {
	Infos []ipsecInfo `json:"infos"`
}

func createIPsec(tree *server.VyosConfigTree, info ipsecInfo)  {
	nicname, err := utils.GetNicNameByIp(info.Vip); utils.PanicOnError(err)

	tree.Setf("vpn ipsec ipsec-interfaces interface %s", nicname)

	// create ike group
	tree.Setf("vpn ipsec ike-group %s proposal 1 dh-group %v", info.Uuid, info.IkeDhGroup)
	tree.Setf("vpn ipsec ike-group %s proposal 1 encryption %v", info.Uuid, info.IkeEncryptionAlgorithm)
	tree.Setf("vpn ipsec ike-group %s proposal 1 hash %v", info.Uuid, info.IkeAuthAlgorithm)

	// create esp group
	if info.Pfs == "" {
		tree.Setf("vpn ipsec esp-group %s pfs disable", info.Uuid)
	} else {
		tree.Setf("vpn ipsec esp-group %s pfs %s", info.Uuid, info.Pfs)
	}
	tree.Setf("vpn ipsec esp-group %s proposal 1 encryption %s", info.Uuid, info.PolicyEncryptionAlgorithm)
	tree.Setf("vpn ipsec esp-group %s proposal 1 hash %s", info.Uuid, info.PolicyAuthAlgorithm)
	tree.Setf("vpn ipsec esp-group %s mode %s", info.Uuid, info.PolicyMode)

	// create peer connection
	utils.Assertf(info.AuthMode == "psk", "vyos plugin only supports authMode 'psk', %s is not supported yet", info.AuthMode)
	tree.Setf("vpn ipsec site-to-site peer %s authentication mode pre-shared-secret", info.PeerAddress)
	tree.Setf("vpn ipsec site-to-site peer %s authentication pre-shared-secret %s", info.PeerAddress, info.AuthKey)
	tree.Setf("vpn ipsec site-to-site peer %s default-esp-group %s", info.PeerAddress, info.Uuid)
	tree.Setf("vpn ipsec site-to-site peer %s ike-group %s", info.PeerAddress, info.Uuid)

	tree.Setf("vpn ipsec site-to-site peer %s local-address %s", info.PeerAddress, info.Vip)
	utils.Assertf(len(info.LocalCidrs) == 1, "localCidrs%v containing more than one CIDR is not supported yet", info.LocalCidrs)
	localCidr := info.LocalCidrs[0]
	for i, remoteCidr := range info.PeerCidrs {
		tree.Setf("vpn ipsec site-to-site peer %v tunnel %v local prefix %v", info.PeerAddress, i+1, localCidr)
		tree.Setf("vpn ipsec site-to-site peer %v tunnel %v remote prefix %v", info.PeerAddress, i+1, remoteCidr)
	}

	// configure firewall
	des := "ipsec-500-udp"
	if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			"destination port 500",
			fmt.Sprintf("description %s", des),
			"protocol udp",
			"action accept",
		)
	}

	des = "ipsec-4500-udp"
	if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			"destination port 4500",
			fmt.Sprintf("description %s", des),
			"protocol udp",
			"action accept",
		)
	}

	des = "ipsec-esp"
	if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %s", des),
			"protocol esp",
			"action accept",
		)
	}

	des = "ipsec-ah"
	if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %s", des),
			"protocol ah",
			"action accept",
		)
	}

	for _, cidr := range info.PeerCidrs {
		des = fmt.Sprintf("IPSEC-%s-%s", info.Uuid, cidr)
		if r := tree.FindFirewallRuleByDescription(nicname, "in", des); r == nil {
			tree.SetFirewallOnInterface(nicname, "in",
				"action accept",
				"state established enable",
				"state related enable",
				"state new enable",
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("source address %v", cidr),
			)
		}
	}

	tree.AttachFirewallToInterface(nicname, "local")
	tree.AttachFirewallToInterface(nicname, "in")

	if info.ExcludeSnat {
		for _, remoteCidr := range info.PeerCidrs {
			des = fmt.Sprintf("ipsec-%s-%s-%s", info.Uuid, localCidr, remoteCidr)
			if r := tree.FindSnatRuleDescription(des); r == nil {
				tree.SetSnat(
					fmt.Sprintf("destination address %v", remoteCidr),
					fmt.Sprintf("source address %v", localCidr),
					fmt.Sprintf("outbound-interface %v", nicname),
					fmt.Sprintf("description %v", des),
					"exclude",
				)
			}
		}
	}
}

func createIPsecConnection(ctx *server.CommandContext) interface{} {
	cmd := &createIPsecCmd{}
	ctx.GetCommand(cmd)

	vyos := server.NewParserFromShowConfiguration()
	tree := vyos.Tree
	for _, info := range cmd.Infos {
		createIPsec(tree, info)
	}
	tree.Apply(false)

	return nil
}

func syncIPsecConnection(ctx *server.CommandContext) interface{} {
	cmd := &syncIPsecCmd{}
	ctx.GetCommand(cmd)

	vyos := server.NewParserFromShowConfiguration()
	tree := vyos.Tree

	tree.Delete("vpn ipsec")

	for _, info := range cmd.Infos {
		createIPsec(tree, info)
	}
	tree.Apply(false)

	return nil
}

func deleteIPsecConnection(ctx *server.CommandContext) interface{} {
	cmd := &deleteIPsecCmd{}
	ctx.GetCommand(cmd)

	vyos := server.NewParserFromShowConfiguration()
	tree := vyos.Tree
	for _, info := range cmd.Infos {
		deleteIPsec(tree, info)
	}
	tree.Apply(false)

	return nil
}

func deleteIPsec(tree *server.VyosConfigTree, info ipsecInfo) {
	nicname, err := utils.GetNicNameByIp(info.Vip); utils.PanicOnError(err)

	tree.Deletef("vpn ipsec ike-group %s", info.Uuid)
	tree.Deletef("vpn ipsec esp-group %s", info.Uuid)
	tree.Deletef("vpn ipsec site-to-site peer %s", info.PeerAddress)

	if info.ExcludeSnat {
		utils.Assertf(len(info.LocalCidrs) == 1, "localCidrs%v containing more than one CIDR is not supported yet", info.LocalCidrs)
		localCidr := info.LocalCidrs[0]

		for _, remoteCidr := range info.PeerCidrs {
			des := fmt.Sprintf("ipsec-%s-%s-%s", info.Uuid, localCidr, remoteCidr)
			if r := tree.FindSnatRuleDescription(des); r != nil {
				r.Delete()
			}
		}
	}

	for _, cidr := range info.PeerCidrs {
		des := fmt.Sprintf("IPSEC-%s-%s", info.Uuid, cidr)
		if r := tree.FindFirewallRuleByDescription(nicname, "in", des); r != nil {
			r.Delete()
		}
	}

	ipsec := tree.Get("vpn ipsec site-to-site peer")
	if ipsec == nil || ipsec.Size() == 0 {
		// no any ipsec connection

		// delete ipsec related rules
		tree.Delete("vpn ipsec")

		// delete firewall
		if r := tree.FindFirewallRuleByDescription(nicname, "local", "ipsec-500-udp"); r != nil {
			r.Delete()
		}
		if r := tree.FindFirewallRuleByDescription(nicname, "local", "ipsec-4500-udp"); r != nil {
			r.Delete()
		}
		if r := tree.FindFirewallRuleByDescription(nicname, "local", "ipsec-esp"); r != nil {
			r.Delete()
		}
		if r := tree.FindFirewallRuleByDescription(nicname, "local", "ipsec-ah"); r != nil {
			r.Delete()
		}
	}
}

func IPsecEntryPoint() {
	server.RegisterAsyncCommandHandler(CREATE_IPSEC_CONNECTION, server.VyosLock(createIPsecConnection))
	server.RegisterAsyncCommandHandler(DELETE_IPSEC_CONNECTION, server.VyosLock(deleteIPsecConnection))
	server.RegisterAsyncCommandHandler(SYNC_IPSEC_CONNECTION, server.VyosLock(syncIPsecConnection))
}
