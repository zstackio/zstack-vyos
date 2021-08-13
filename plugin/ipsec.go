package plugin

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"sort"
	"strconv"
	"strings"
	"time"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
)

const (
	CREATE_IPSEC_CONNECTION = "/vyos/createipsecconnection"
	DELETE_IPSEC_CONNECTION = "/vyos/deleteipsecconnection"
	SYNC_IPSEC_CONNECTION   = "/vyos/syncipsecconnection"
	UPDATE_IPSEC_CONNECTION = "/vyos/updateipsecconnection"

	IPSecInfoMaxSize = 256

	VYOSHA_IPSEC_SCRIPT = "/home/vyos/zvr/keepalived/script/ipsec.sh"

	/* because strongswan 4.5.2 rekey will fail with aliyun ipsec vpn,
	a work around method is to restart the vpn before the rekey happened */
	IPSecIkeRekeyInterval       = 86400 /*  24 * 3600 seconds */
	IPSecIkeRekeyIntervalMargin = 600   /* restart the vpn 10 mins before rekey */
	IPSecRestartInterval        = IPSecIkeRekeyInterval - IPSecIkeRekeyIntervalMargin

	ipsecAddressGroup = "ipsec-group"
)

var AutoRestartVpn = false
var AutoRestartThreadCreated = false

type ipsecInfo struct {
	Uuid                      string   `json:"uuid"`
	State                     string   `json:"state"`
	LocalCidrs                []string `json:"localCidrs"`
	PeerAddress               string   `json:"peerAddress"`
	RemoteId                  string   `json:"remoteId"`
	AuthMode                  string   `json:"authMode"`
	AuthKey                   string   `json:"authKey"`
	Vip                       string   `json:"vip"`
	PublicNic                 string   `json:"publicNic"`
	IkeAuthAlgorithm          string   `json:"ikeAuthAlgorithm"`
	IkeEncryptionAlgorithm    string   `json:"ikeEncryptionAlgorithm"`
	IkeDhGroup                int      `json:"ikeDhGroup"`
	PolicyAuthAlgorithm       string   `json:"policyAuthAlgorithm"`
	PolicyEncryptionAlgorithm string   `json:"policyEncryptionAlgorithm"`
	Pfs                       string   `json:"pfs"`
	PolicyMode                string   `json:"policyMode"`
	TransformProtocol         string   `json:"transformProtocol"`
	PeerCidrs                 []string `json:"peerCidrs"`
	ExcludeSnat               bool     `json:"excludeSnat"`
	ModifiedItems             []string `json:"modifiedItems"`
}

type createIPsecCmd struct {
	Infos          []ipsecInfo `json:"infos"`
	AutoRestartVpn bool        `json:"autoRestartVpn"`
}

type deleteIPsecCmd struct {
	Infos []ipsecInfo `json:"infos"`
}

type syncIPsecCmd struct {
	Infos          []ipsecInfo `json:"infos"`
	AutoRestartVpn bool        `json:"autoRestartVpn"`
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
		peers = append(peers, peerStr[len(peerStr)-1])
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
func isVpnPeerUp(peer string) (status bool) {
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
		Command: fmt.Sprintf("/opt/vyatta/bin/sudo-users/vyatta-op-vpn.pl --show-ipsec-sa-peer=%s | grep -w 'up'", peer),
	}
	ret, _, _, err := bash.RunWithReturn()
	/* command fail, will try again */
	if err != nil {
		return false
	}

	/* ret = 0 means some tunnel is up */
	if ret == 0 {
		return true
	} else {
		return false
	}
}

func isVpnAllPeersUp() bool {
	peers := getIPsecPeers()
	for _, peer := range peers {
		if !isVpnPeerUp(peer) {
			return false
		}
	}

	return true
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
func restartVpnAfterConfig() {
	if isVpnAllPeersUp() {
		restartIPSecVpnTimer()
		return
	}

	/* wait 20 seconds to let all peer go up */
	time.Sleep(20 * time.Second)

	/* it need a log time to make sure checkVpnState can find new created tunnels */
	err := utils.Retry(func() error {
		if isVpnAllPeersUp() {
			return nil
		}

		if utils.Vyos_version == utils.VYOS_1_1_7 && len(getIPsecPeers()) >= 2 {
			bash := utils.Bash{
				Command: "sudo ipsec restart",
			}
			bash.Run()
		} else {
			b := utils.Bash{
				Command: "pidof starter; if [ $? -eq 0 ]; then sudo ipsec reload; else sudo ipsec restart; fi",
			}
			b.Run()
		}

		return fmt.Errorf("there is some ipsec peer is not up")
	}, 3, 20)

	restartIPSecVpnTimer()
	if err != nil {
		log.Warn(fmt.Sprintf("setup ip sec tunnel failed: %s", err))
	}
}

func syncIpSecRulesByIptables() {
	snatRules := []utils.IptablesRule{}
	localfilterRules := make(map[string][]utils.IptablesRule)
	filterRules := make(map[string][]utils.IptablesRule)
	vipNicNameMap := make(map[string]string)

	for _, info := range ipsecMap {
		if _, ok := vipNicNameMap[info.Vip]; ok {
			continue
		}
		nicname, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)
		vipNicNameMap[info.Vip] = nicname
	}

	for _, info := range ipsecMap {
		nicname, _ := vipNicNameMap[info.Vip]
		if _, ok := localfilterRules[nicname]; ok {
			continue
		}

		rule := utils.NewIptablesRule(utils.UDP, info.PeerAddress, "", 0, 500, nil, utils.RETURN, utils.IpsecRuleComment)
		localfilterRules[nicname] = append(localfilterRules[nicname], rule)

		rule = utils.NewIptablesRule(utils.UDP, info.PeerAddress, "", 0, 4500, nil, utils.RETURN, utils.IpsecRuleComment)
		localfilterRules[nicname] = append(localfilterRules[nicname], rule)

		rule = utils.NewIptablesRule(utils.ESP, info.PeerAddress, "", 0, 0, nil, utils.RETURN, utils.IpsecRuleComment)
		localfilterRules[nicname] = append(localfilterRules[nicname], rule)

		rule = utils.NewIptablesRule(utils.AH, info.PeerAddress, "", 0, 0, nil, utils.RETURN, utils.IpsecRuleComment)
		localfilterRules[nicname] = append(localfilterRules[nicname], rule)
	}

	for _, info := range ipsecMap {
		nicname, _ := vipNicNameMap[info.Vip]
		for _, remoteCidr := range info.PeerCidrs {
			rule := utils.NewIptablesRule("", remoteCidr, "", 0, 0, []string{utils.NEW, utils.RELATED, utils.ESTABLISHED},
				utils.RETURN, utils.IpsecRuleComment+info.Uuid)
			filterRules[nicname] = append(filterRules[nicname], rule)

			/* add remote cidr rule in local chain, so that remove cidr can access lb service of vpc */
			rule = utils.NewIptablesRule("", remoteCidr, "", 0, 0, []string{utils.NEW, utils.RELATED, utils.ESTABLISHED},
				utils.RETURN, utils.IpsecRuleComment+info.Uuid)
			localfilterRules[nicname] = append(localfilterRules[nicname], rule)
		}

		/* nat rule */
		for _, srcCidr := range info.LocalCidrs {
			for _, remoteCidr := range info.PeerCidrs {
				rule := utils.NewIpsecsIptablesRule("", srcCidr, remoteCidr, 0, 0, nil, utils.RETURN,
					utils.IpsecRuleComment+info.Uuid, "", nicname)
				snatRules = append(snatRules, rule)
			}
		}
	}

	if err := utils.SyncNatRule(snatRules, nil, utils.IpsecRuleComment); err != nil {
		log.Warnf("ipsec SyncNatRule failed %s", err.Error())
		utils.PanicOnError(err)
	}

	if err := utils.SyncLocalAndInFirewallRule(filterRules, localfilterRules, utils.IpsecRuleComment); err != nil {
		log.Warnf("ipsec SyncFirewallRule in failed %s", err.Error())
		utils.PanicOnError(err)
	}
}

func createIPsec(tree *server.VyosConfigTree, info ipsecInfo) {
	nicname, err := utils.GetNicNameByMac(info.PublicNic)
	utils.PanicOnError(err)

	tree.Setf("vpn ipsec ipsec-interfaces interface %s", nicname)

	// create ike group
	tree.Setf("vpn ipsec ike-group %s lifetime %d", info.Uuid, IPSecIkeRekeyInterval)
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
	tree.Setf("vpn ipsec site-to-site peer %s authentication id %s", info.PeerAddress, info.Vip)
	if info.RemoteId != "" {
		tree.Setf("vpn ipsec site-to-site peer %s authentication remote-id", info.RemoteId)
	}
	tree.Setf("vpn ipsec site-to-site peer %s default-esp-group %s", info.PeerAddress, info.Uuid)
	tree.Setf("vpn ipsec site-to-site peer %s ike-group %s", info.PeerAddress, info.Uuid)

	tree.Setf("vpn ipsec site-to-site peer %s local-address %s", info.PeerAddress, info.Vip)

	tunnelNo := 1
	sort.Strings(info.LocalCidrs)
	sort.Strings(info.PeerCidrs)
	for _, localCidr := range info.LocalCidrs {
		for _, remoteCidr := range info.PeerCidrs {
			tree.Setf("vpn ipsec site-to-site peer %v tunnel %v local prefix %v", info.PeerAddress, tunnelNo, localCidr)
			tree.Setf("vpn ipsec site-to-site peer %v tunnel %v remote prefix %v", info.PeerAddress, tunnelNo, remoteCidr)
			tunnelNo++
		}
	}
	tunnels := tree.Getf("vpn ipsec site-to-site peer %v tunnel", info.PeerAddress)
	/* if local cidr or remote cidr decrease, delete old config */
	for _, t := range tunnels.Children() {
		num, _ := strconv.Atoi(t.Name())
		if num >= tunnelNo {
			tree.Deletef("vpn ipsec site-to-site peer %v tunnel %s", info.PeerAddress, t.Name())
		}
	}

	if utils.IsSkipVyosIptables() {
		return
	}

	//create eipaddress group
	tree.SetGroup("address", ipsecAddressGroup, info.PeerAddress)

	// configure firewall
	des := "ipsec-500-udp"
	if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			"destination port 500",
			fmt.Sprintf("source group address-group %s", ipsecAddressGroup),
			fmt.Sprintf("description %s", des),
			"protocol udp",
			"action accept",
		)
	}

	des = "ipsec-4500-udp"
	if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			"destination port 4500",
			fmt.Sprintf("source group address-group %s", ipsecAddressGroup),
			fmt.Sprintf("description %s", des),
			"protocol udp",
			"action accept",
		)
	}

	des = "ipsec-esp"
	if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %s", des),
			fmt.Sprintf("source group address-group %s", ipsecAddressGroup),
			"protocol esp",
			"action accept",
		)
	}

	des = "ipsec-ah"
	if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %s", des),
			fmt.Sprintf("source group address-group %s", ipsecAddressGroup),
			"protocol ah",
			"action accept",
		)
	}

	for _, cidr := range info.PeerCidrs {
		des = fmt.Sprintf("IPSEC-%s-%s", info.Uuid, cidr)
		if r := tree.FindFirewallRuleByDescription(nicname, "in", des); r == nil {
			tree.SetZStackFirewallRuleOnInterface(nicname, "front", "in",
				"action accept",
				"state established enable",
				"state related enable",
				"state new enable",
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("source address %v", cidr),
			)
		}

		/* add remote cidr rule in local chain, so that remove cidr can access lb service of vpc */
		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
			tree.SetZStackFirewallRuleOnInterface(nicname, "front", "local",
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
							tree.Getf("nat source rule %v", num), tree.Getf("nat source rule %v", f)))
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
	AutoRestartVpn = cmd.AutoRestartVpn

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
	AutoRestartVpn = cmd.AutoRestartVpn

	vyos := server.NewParserFromShowConfiguration()
	tree := vyos.Tree
	ipsecMap = make(map[string]ipsecInfo, IPSecInfoMaxSize)

	for _, info := range cmd.Infos {
		ipsecMap[info.Uuid] = info
		createIPsec(tree, info)
	}

	if len(cmd.Infos) > 0 {
		openNatTraversal(tree)
	}
	tree.Apply(false)

	if utils.IsSkipVyosIptables() {
		syncIpSecRulesByIptables()
	}

	if len(ipsecMap) > 0 {
		go restartVpnAfterConfig()
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

	bash := utils.Bash{
		Command: fmt.Sprintf("ip rule list | grep 32766"),
	}
	_, out, _, _ := bash.RunWithReturn()
	if out == "" {
		bash := utils.Bash{
			Command: fmt.Sprintf("sudo ip rule add from all table main pref 32766"),
		}
		_, _, _, err := bash.RunWithReturn()
		utils.PanicOnError(err)
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
	nicname, err := utils.GetNicNameByMac(info.PublicNic)
	utils.PanicOnError(err)

	tree.Deletef("vpn ipsec ike-group %s", info.Uuid)
	tree.Deletef("vpn ipsec esp-group %s", info.Uuid)
	tree.Deletef("vpn ipsec site-to-site peer %s", info.PeerAddress)

	if utils.IsSkipVyosIptables() {
		return
	}

	/* in sync ipsec, we don't know what is localcidr, remotecidr is missing
	 * so use reg expression to delete all rules
	 */
	if r := tree.FindGroupByNameValue(info.PeerAddress, ipsecAddressGroup, "address"); r != nil {
		r.Delete()
	}

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
			break
		}

		if r := tree.FindFirewallRuleByDescriptionRegex(nicname, "local", des, utils.StringRegCompareFn); r != nil {
			r.Delete()
		} else {
			break
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
			tree.Setf("vpn ipsec site-to-site peer %v tunnel %v disable", info.PeerAddress, i+1)
		}
	} else if info.State == "Enabled" {
		for i, _ := range info.PeerCidrs {
			tree.Deletef("vpn ipsec site-to-site peer %v tunnel %v disable", info.PeerAddress, i+1)
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
		for _, item := range info.ModifiedItems {
			if item == "State" {
				updateIPsecConnectionState(tree, cmd.Infos[0])
			}
		}
	}

	return nil
}

func writeIpsecHaScript(enable bool) {
	if !utils.IsHaEnabled() {
		return
	}

	if enable {
		srcFile := "/home/vyos/zvr/keepalived/temp/ipsec.sh"
		_, er := utils.CopyFile(srcFile, VYOSHA_IPSEC_SCRIPT)
		utils.PanicOnError(er)
	} else {
		conent := "echo 'no ipsec configured'"
		err := ioutil.WriteFile(VYOSHA_IPSEC_SCRIPT, []byte(conent), 0755)
		utils.PanicOnError(err)
	}

}

func getIkeUptime(peer string) int {
	/*
		* $ /opt/vyatta/bin/sudo-users/vyatta-op-vpn.pl --show-ike-sa-peer=10.86.5.142
		Peer ID / IP                            Local ID / IP
		------------                            -------------
		10.86.5.142                             10.86.5.144

		    State  Encrypt  Hash    D-H Grp  NAT-T  A-Time  L-Time
		    -----  -------  ----    -------  -----  ------  ------
		    up     3des     sha1    2        no     5400    86400
	*/
	bash := utils.Bash{
		Command: fmt.Sprintf("/opt/vyatta/bin/sudo-users/vyatta-op-vpn.pl --show-ike-sa-peer=%s | grep -A 2 A-Time | grep up", peer),
	}
	ret, o, _, err := bash.RunWithReturn()
	if ret != 0 || err != nil {
		return 0
	}

	var atime, ltime int
	var state, encrypt, hash, dhGrp, nat string
	o = strings.TrimSpace(o)
	len, err := fmt.Sscanf(o, "%s %s %s %s %s %d %d", &state, &encrypt, &hash, &dhGrp, &nat, &atime, &ltime)
	if err != nil || len < 7 {
		return 0
	}
	return ltime - atime
}

func restartIPSecVpnTimer() {
	if AutoRestartThreadCreated {
		return
	}

	AutoRestartThreadCreated = true

	peers := getIPsecPeers()
	ikeUpTime := 0
	for _, peer := range peers {
		t := getIkeUptime(peer)
		if t > ikeUpTime {
			ikeUpTime = t
		}
	}

	log.Debugf("ike uptime %d", ikeUpTime)
	interval := ikeUpTime - IPSecIkeRekeyIntervalMargin
	if interval <= 0 {
		interval = 1
	}

	restartTicker := time.NewTicker(time.Duration(interval) * time.Second)
	go func() {
		for {
			select {
			case <-restartTicker.C:
				if !AutoRestartVpn {
					return
				}

				log.Debugf("restart vpn process because config flag: AutoRestartVpn ")
				utils.Retry(func() error {
					bash := utils.Bash{
						Command: "pidof starter; if [ $? -eq 0 ]; then sudo ipsec reload; else sudo ipsec restart; fi",
						NoLog:   false,
					}
					_, _, _, err := bash.RunWithReturn()
					return err
				}, 3, 60)

				restartTicker = time.NewTicker(time.Second * IPSecRestartInterval)
			}
		}
	}()
}

func IPsecEntryPoint() {
	ipsecMap = make(map[string]ipsecInfo, IPSecInfoMaxSize)
	server.RegisterAsyncCommandHandler(CREATE_IPSEC_CONNECTION, server.VyosLock(createIPsecConnection))
	server.RegisterAsyncCommandHandler(DELETE_IPSEC_CONNECTION, server.VyosLock(deleteIPsecConnection))
	server.RegisterAsyncCommandHandler(SYNC_IPSEC_CONNECTION, server.VyosLock(syncIPsecConnection))
	server.RegisterAsyncCommandHandler(UPDATE_IPSEC_CONNECTION, server.VyosLock(updateIPsecConnection))
}
