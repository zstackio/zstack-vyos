package plugin

import (
	"zvr/server"
	"zvr/utils"
	"fmt"
)

const(
	CREATE_IPSEC_CONNECTION = "/vyos/createipsecconnection"
	DELETE_IPSEC_CONNECTION = "/vyos/deleteipsecconnection"
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
}

type createIPsecCmd struct {
	infos []ipsecInfo
}

type deleteIPsecCmd struct {
	infos []ipsecInfo
}

func createIPsec(tree *server.VyosConfigTree, info ipsecInfo)  {
	nicname, err := utils.GetNicNameByIp(info.Vip); utils.PanicOnError(err)

	tree.Setf("set vpn ipsec ipsec-interfaces interface %s", nicname)

	// create ike group
	tree.Setf("set vpn ipsec ike-group %s proposal 1 dh-group %v", info.Uuid, info.IkeDhGroup)
	tree.Setf("set vpn ipsec ike-group %s proposal 1 encryption %v", info.Uuid, info.IkeEncryptionAlgorithm)
	tree.Setf("set vpn ipsec ike-group %s proposal 1 hash %v", info.Uuid, info.IkeAuthAlgorithm)

	// create esp group
	if info.Pfs == "" {
		tree.Setf("set vpn ipsec esp-group %s pfs disable", info.Uuid)
	} else {
		tree.Setf("set vpn ipsec esp-group %s pfs %s", info.Uuid, info.Pfs)
	}
	tree.Setf("set vpn ipsec esp-group %s proposal 1 encryption %s", info.Uuid, info.PolicyEncryptionAlgorithm)
	tree.Setf("set vpn ipsec esp-group %s proposal 1 hash %s", info.Uuid, info.PolicyAuthAlgorithm)
	tree.Setf("set vpn ipsec esp-group %s mode %s", info.Uuid, info.PolicyMode)

	// create peer connection
	utils.Assertf(info.AuthMode == "psk", "vyos plugin only supports authMode 'psk', %s is not supported yet", info.AuthMode)
	tree.Setf("set vpn ipsec site-to-site peer %s authentication mode pre-shared-secret", info.PeerAddress)
	tree.Setf("set vpn ipsec site-to-site peer %s authentication pre-shared-secret %s", info.PeerAddress, info.AuthKey)
	tree.Setf("set vpn ipsec site-to-site peer %s default-esp-group %s", info.PeerAddress, info.Uuid)
	tree.Setf("set vpn ipsec site-to-site peer %s ike-group %s", info.PeerAddress, info.Uuid)

	tree.Setf("set vpn ipsec site-to-site peer %s local-address %s", info.PeerAddress, info.Vip)
	utils.Assertf(len(info.LocalCidrs) == 1, "localCidrs%v containing more than one CIDR is not supported yet", info.LocalCidrs)
	localCidr := info.LocalCidrs[0]
	for i, remoteCidr := range info.PeerCidrs {
		tree.Setf("set vpn ipsec site-to-site peer %v tunnel %v local prefix %v", info.PeerAddress, i+1, localCidr)
		tree.Setf("set vpn ipsec site-to-site peer %v tunnel %v remote prefix %v", info.PeerAddress, i+1, remoteCidr)
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

	tree.AttachFirewallToInterface(nicname, "local")
}

func createIPsecConnection(ctx *server.CommandContext) interface{} {
	cmd := &createIPsecCmd{}
	ctx.GetCommand(cmd)

	vyos := server.NewParserFromShowConfiguration()
	tree := vyos.Tree
	for _, info := range cmd.infos {
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
	for _, info := range cmd.infos {
		deleteIPsec(tree, info)
	}
	tree.Apply(false)

	return nil
}

func deleteIPsec(tree *server.VyosConfigTree, info ipsecInfo) {
	nicname, err := utils.GetNicNameByIp(info.Vip); utils.PanicOnError(err)

	tree.Deletef("delete vpn ipsec ipsec-interfaces interface %s", nicname)
	tree.Deletef("delete vpn ipsec ike-group %s", info.Uuid)
	tree.Deletef("delete vpn ipsec esp-group %s", info.Uuid)
	tree.Deletef("delete vpn ipsec site-to-site peer %s", info.PeerAddress)

	ipsec := tree.Get("vpn ipsec site-to-site")
	if ipsec == nil || ipsec.Size() == 0 {
		// no ipsec rule, delete firewall
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
}
