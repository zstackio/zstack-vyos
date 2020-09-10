package plugin

import (
	"zvr/server"
	"zvr/utils"
	"fmt"
	"strings"
	"time"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
)

const(
	CREATE_IPSEC_CONNECTION = "/vyos/createipsecconnection"
	DELETE_IPSEC_CONNECTION = "/vyos/deleteipsecconnection"
	SYNC_IPSEC_CONNECTION = "/vyos/syncipsecconnection"
	UPDATE_IPSEC_CONNECTION = "/vyos/updateipsecconnection"

	IPSecInfoMaxSize = 256

	VYOSHA_IPSEC_SCRIPT = "/home/vyos/zvr/keepalived/script/ipsec.sh"

	/* because strongswan 4.5.2 rekey will fail, a work around method is to restart the vpn before the rekey happened */
	IPSecIkeRekeyInterval = 28800 /*  8 * 3600 seconds */
	IPSecRestartInterval = IPSecIkeRekeyInterval - 600 /* restart the vpn 10 mins before rekey */
)

type ipsecInfo struct {
	Uuid string `json:"uuid"`
	State string `json:"state"`
	LocalCidrs []string `json:"localCidrs"`
	PeerAddress string `json:"peerAddress"`
	AuthMode string `json:"authMode"`
	AuthKey string `json:"authKey"`
	Vip string `json:"vip"`
	PublicNic string `json:"publicNic"`
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
	ModifiedItems []string `json:"modifiedItems"`
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

type updateIPsecReq struct {
	Infos []ipsecInfo `json:"infos"`
}

type updateIPsecReply struct {
	Infos []ipsecInfo `json:"infos"`
}

var ipsecMap map[string]ipsecInfo

func getIPsecPeers() (peers []string) {
	vyos := server.NewParserFromShowConfiguration()
	tree := vyos.Tree

	peers = []string{}
	rs := tree.Getf("vpn ipsec site-to-site peer")
	if rs == nil {
		return
	}

	for _, r := range rs.Children() {
		peerStr := strings.Split(r.String(), " ")
		peers = append(peers, peerStr[len(peerStr) - 1])
	}

	return
}

/* /opt/vyatta/bin/sudo-users/vyatta-op-vpn.pl is a tool to display ipsec status, it has options:
           "show-ipsec-sa!"                 => \$show_ipsec_sa,
           "show-ipsec-sa-detail!"          => \$show_ipsec_sa_detail,
           "get-peers-for-cli!"             => \$get_peers_for_cli,
           "get-conn-for-cli=s"             => \$get_conn_for_cli,
           "show-ipsec-sa-peer=s"           => \$show_ipsec_sa_peer,
           "show-ipsec-sa-peer-detail=s"    => \$show_ipsec_sa_peer_detail,
           "show-ipsec-sa-natt!"            => \$show_ipsec_sa_natt,
           "show-ipsec-sa-stats!"           => \$show_ipsec_sa_stats,
           "show-ipsec-sa-stats-peer=s"     => \$show_ipsec_sa_stats_peer,
           "show-ipsec-sa-stats-conn=s{2}"  => \@show_ipsec_sa_stats_conn,
           "show-ipsec-sa-conn-detail=s{2}" => \@show_ipsec_sa_conn_detail,
           "show-ipsec-sa-conn=s{2}"        => \@show_ipsec_sa_conn,
           "show-ike-sa!"                   => \$show_ike_sa,
           "show-ike-sa-peer=s"             => \$show_ike_sa_peer,
           "show-ike-sa-natt!"              => \$show_ike_sa_natt,
           "show-ike-status!"               => \$show_ike_status,
           "show-ike-secrets!"              => \$show_ike_secrets);
           */

/* get vpn peer status */
func getVpnPeerStatus(peer string)  (status bool) {
	/*
	/opt/vyatta/bin/sudo-users/vyatta-op-vpn.pl --show-ipsec-sa-peer=10.86.0.3
	Peer ID / IP                            Local ID / IP
	------------                            -------------
	10.86.0.3                               10.86.0.2

    	Tunnel  State  Bytes Out/In   Encrypt  Hash    NAT-T  A-Time  L-Time  Proto
    	------  -----  -------------  -------  ----    -----  ------  ------  -----
    	1       down   n/a            n/a      n/a     no     0       3600    all
	*/
	bash := utils.Bash{
		Command: fmt.Sprintf("/opt/vyatta/bin/sudo-users/vyatta-op-vpn.pl --show-ipsec-sa-peer=%s | grep -w 'down'", peer),
	}
	ret, _, _, err := bash.RunWithReturn()
	/* command fail, will try again */
	if (err != nil) {
		return false
	}

	/* ret = 0 means some tunnel is down */
	if (ret == 0) {
		return false
	} else {
		return true
	}
}

func checkVpnStateUp()  error {
	peers := getIPsecPeers()
	peersRestart := []string{}
	for _, peer := range peers {
		if (getVpnPeerStatus(peer) == false) {
			peersRestart = append(peersRestart, peer)
		}
	}

	if (len(peersRestart) != 0) {
		return fmt.Errorf("peers [%s] still has tunnel down after 4 times retry", peersRestart)
	}

	return nil
}

/* /opt/vyatta/bin/sudo-users/vyatta-vpn-op.pl is a tool to change ipsec config, it has options:
	clear-vpn-ipsec-process
	show-vpn-debug
	show-vpn-debug-detail
	get-all-peers
	get-tunnels-for-peer
	clear-tunnels-for-peer
	clear-specific-tunnel-for-peer
	clear-vtis-for-peer
	*/
func restartVpnAfterConfig()  {
	if (checkVpnStateUp() == nil) {
		return
	}

	bash := utils.Bash{
		Command: "/opt/vyatta/bin/sudo-users/vyatta-vpn-op.pl -op clear-vpn-ipsec-process",
	}
	bash.Run()
	time.Sleep(20 * time.Second)

	/* it need a log time to make sure checkVpnState can find new created tunnels */
	err := utils.Retry(func() (err error) {
		if err = checkVpnStateUp(); err != nil {
			bash.Run()
		}

		return err
	}, 3, 20);log.Warn(fmt.Sprintf("setup ip sec tunnel failed: %s", err))
}

func syncIpSecRulesByIptables()  {
	snatRules := []utils.IptablesRule{}
	localfilterRules := make(map[string][]utils.IptablesRule)
	filterRules := make(map[string][]utils.IptablesRule)
	vipNicNameMap := make(map[string]string)

	for _, info := range ipsecMap {
		if _, ok := vipNicNameMap[info.Vip] ; ok {
			continue
		}
		nicname, err := utils.GetNicNameByMac(info.PublicNic); utils.PanicOnError(err)
		vipNicNameMap[info.Vip] = nicname
	}

	for _, info := range ipsecMap {
		nicname, _ := vipNicNameMap[info.Vip]
		if _, ok := localfilterRules[nicname]; ok {
			continue
		}

		rule := utils.NewIptablesRule(utils.UDP,  "", "", 0, 500, nil, utils.RETURN, utils.IpsecRuleComment)
		localfilterRules[nicname] = append(localfilterRules[nicname], rule)

		rule = utils.NewIptablesRule(utils.UDP,  "", "", 0, 4500, nil, utils.RETURN, utils.IpsecRuleComment)
		localfilterRules[nicname] = append(localfilterRules[nicname], rule)

		rule = utils.NewIptablesRule(utils.ESP,  "", "", 0, 0, nil, utils.RETURN, utils.IpsecRuleComment)
		localfilterRules[nicname] = append(localfilterRules[nicname], rule)

		rule = utils.NewIptablesRule(utils.AH,  "", "", 0, 0, nil, utils.RETURN, utils.IpsecRuleComment)
		localfilterRules[nicname] = append(localfilterRules[nicname], rule)
	}

	for _, info := range ipsecMap {
		nicname, _ := vipNicNameMap[info.Vip]
		for _, remoteCidr := range info.PeerCidrs {
			rule := utils.NewIptablesRule("",  remoteCidr, "", 0, 0, []string{utils.NEW, utils.RELATED, utils.ESTABLISHED},
				utils.RETURN, utils.IpsecRuleComment + info.Uuid)
			filterRules[nicname] = append(filterRules[nicname], rule)
		}

		/* nat rule */
		for _, srcCidr := range info.LocalCidrs {
			for _, remoteCidr := range info.PeerCidrs {
				rule := utils.NewIpsecsIptablesRule("", srcCidr, remoteCidr, 0, 0, nil, utils.RETURN,
					utils.IpsecRuleComment + info.Uuid, "", nicname)
				snatRules = append(snatRules, rule)
			}
		}
	}

	if err := utils.SyncNatRule(snatRules, nil, utils.IpsecRuleComment); err != nil {
		log.Warn("ipsec SyncNatRule failed %s", err.Error())
		utils.PanicOnError(err)
	}

	if err := utils.SyncLocalAndInFirewallRule(filterRules, localfilterRules, utils.IpsecRuleComment); err != nil {
		log.Warn("ipsec SyncFirewallRule in failed %s", err.Error())
		utils.PanicOnError(err)
	}
}

func createIPsec(tree *server.VyosConfigTree, info ipsecInfo)  {
	nicname, err := utils.GetNicNameByMac(info.PublicNic); utils.PanicOnError(err)

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

	tunnelNo := 1
	for _, localCidr := range info.LocalCidrs {
		for _, remoteCidr := range info.PeerCidrs {
			tree.Setf("vpn ipsec site-to-site peer %v tunnel %v local prefix %v", info.PeerAddress, tunnelNo, localCidr)
			tree.Setf("vpn ipsec site-to-site peer %v tunnel %v remote prefix %v", info.PeerAddress, tunnelNo, remoteCidr)
			tunnelNo++
		}
	}

	if utils.IsSkipVyosIptables() {
		return
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
			tree.SetZStackFirewallRuleOnInterface(nicname, "front","in",
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
		for _, localCidr := range info.LocalCidrs {
			for _, remoteCidr := range info.PeerCidrs {
				des = fmt.Sprintf("ipsec-%s-%s-%s", info.Uuid, localCidr, remoteCidr)
				if r := tree.FindSnatRuleDescription(des); r == nil {
					num := tree.SetSnatExclude(
						fmt.Sprintf("destination address %v", remoteCidr),
						fmt.Sprintf("source address %v", localCidr),
						fmt.Sprintf("outbound-interface %v", nicname),
						fmt.Sprintf("description %v", des),
					)
					if f := tree.FindFirstNotExcludeSNATRule(1); num != 1 && num > f {
						/*there has not been run here never*/
						utils.LogError(fmt.Errorf("there is SNAT rule number unexcepted, rule:%v %v",
							tree.Getf("nat source rule %v", num),  tree.Getf("nat source rule %v", f)))
						tree.SwapSnatRule(num, f)
						num = f
					}
					tree.SetSnatWithRuleNumber(num, "exclude")
				}
			}
		}
	}
}

func openNatTraversal(tree *server.VyosConfigTree) {
	natT := tree.Get("vpn ipsec nat-traversal")
	if natT == nil {
		tree.Setf("vpn ipsec nat-traversal enable")
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

	openNatTraversal(tree)
	tree.Apply(false)

	for _, info := range cmd.Infos {
		ipsecMap[info.Uuid] = info
	}

	if utils.IsSkipVyosIptables() {
		syncIpSecRulesByIptables()
	}

	go restartVpnAfterConfig()

	writeIpsecHaScript(true)

	return nil
}

func syncIPsecConnection(ctx *server.CommandContext) interface{} {
	cmd := &syncIPsecCmd{}
	ctx.GetCommand(cmd)

	vyos := server.NewParserFromShowConfiguration()
	tree := vyos.Tree

	ipsecMap = make(map[string]ipsecInfo, IPSecInfoMaxSize)

	for _, info := range cmd.Infos {
		ipsecMap[info.Uuid] = info
		deleteIPsec(tree, info)
		createIPsec(tree, info)
	}

	if len(cmd.Infos) > 0 {
		openNatTraversal(tree)
	}
	tree.Apply(false)

	if utils.IsSkipVyosIptables() {
		syncIpSecRulesByIptables()
	}

	go restartVpnAfterConfig()

	if len(ipsecMap) > 0 {
		writeIpsecHaScript(true)
	} else {
		writeIpsecHaScript(false)
	}

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

	for _, info := range cmd.Infos {
		delete(ipsecMap, info.Uuid)
	}
	if utils.IsSkipVyosIptables() {
		syncIpSecRulesByIptables()
	}

	if len(ipsecMap) > 0 {
		writeIpsecHaScript(true)
	} else {
		writeIpsecHaScript(false)
	}

	return nil
}

func deleteIPsec(tree *server.VyosConfigTree, info ipsecInfo) {
	nicname, err := utils.GetNicNameByMac(info.PublicNic); utils.PanicOnError(err)

	tree.Deletef("vpn ipsec ike-group %s", info.Uuid)
	tree.Deletef("vpn ipsec esp-group %s", info.Uuid)
	tree.Deletef("vpn ipsec site-to-site peer %s", info.PeerAddress)

	if utils.IsSkipVyosIptables() {
		return
	}

	/* in sync ipsec, we don't know what is localcidr, remotecidr is missing
	 * so use reg expression to delete all rules
	 */
	des := fmt.Sprintf("^ipsec-%s-", info.Uuid)
	for {
		if r := tree.FindSnatRuleDescriptionRegex(des, utils.StringRegCompareFn); r != nil {
			r.Delete()
		} else {
			break
		}
	}

	des = fmt.Sprintf("^IPSEC-%s-", info.Uuid)
	for {
		if r := tree.FindFirewallRuleByDescriptionRegex(nicname, "in", des, utils.StringRegCompareFn); r != nil {
			r.Delete()
		} else {
			break;
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

func updateIPsecConnectionState(tree *server.VyosConfigTree, info ipsecInfo) {
	if info.State == "Disabled" {
		for i, _ := range info.PeerCidrs {
			tree.Setf("vpn ipsec site-to-site peer %v tunnel %v disable", info.PeerAddress, i + 1);
		}
	} else if (info.State == "Enabled"){
		for i, _ := range info.PeerCidrs {
			tree.Deletef("vpn ipsec site-to-site peer %v tunnel %v disable", info.PeerAddress, i + 1)
		}
	}
	tree.Apply(false)
}

func updateIPsecConnection(ctx *server.CommandContext) interface{} {
	cmd := &updateIPsecReq{}
	ctx.GetCommand(cmd)

	vyos := server.NewParserFromShowConfiguration()
	tree := vyos.Tree

	for _, info := range cmd.Infos {
		for _, item := range info.ModifiedItems{
			if item == "State" {
				updateIPsecConnectionState(tree, cmd.Infos[0])
		    }
		}
	}

	return nil
}

func writeIpsecHaScript(enable bool)  {
	if !utils.IsHaEabled() {
		return
	}

	var conent string
	if enable {
		conent = "sudo /opt/vyatta/bin/sudo-users/vyatta-vpn-op.pl -op clear-vpn-ipsec-process"
	} else {
		conent = "echo 'no ipsec configured'"
	}

	err := ioutil.WriteFile(VYOSHA_IPSEC_SCRIPT, []byte(conent), 0755); utils.PanicOnError(err)
}

func restartIPSecVpnTimer()  {
	restartTicker := time.NewTicker(time.Second * IPSecRestartInterval)
	/* restart the vpn if vpn is already created */
	bash := utils.Bash{
		Command: "/opt/vyatta/bin/sudo-users/vyatta-vpn-op.pl -op clear-vpn-ipsec-process",
		NoLog: false,
	}
	bash.Run()

	go func() {
		for {
			select {
			case <- restartTicker.C:
				utils.Retry(func() error {
					bash := utils.Bash{
						Command: "/opt/vyatta/bin/sudo-users/vyatta-vpn-op.pl -op clear-vpn-ipsec-process",
						NoLog: false,
					}
					_, _, _, err := bash.RunWithReturn()
					return err
				}, 3, 60)
			}
		}
	} ()
}

func IPsecEntryPoint() {
	ipsecMap = make(map[string]ipsecInfo, IPSecInfoMaxSize)
	server.RegisterAsyncCommandHandler(CREATE_IPSEC_CONNECTION, server.VyosLock(createIPsecConnection))
	server.RegisterAsyncCommandHandler(DELETE_IPSEC_CONNECTION, server.VyosLock(deleteIPsecConnection))
	server.RegisterAsyncCommandHandler(SYNC_IPSEC_CONNECTION, server.VyosLock(syncIPsecConnection))
	server.RegisterAsyncCommandHandler(UPDATE_IPSEC_CONNECTION, server.VyosLock(updateIPsecConnection))
	restartIPSecVpnTimer()
}
