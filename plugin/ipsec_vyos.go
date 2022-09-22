package plugin

import (
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
)

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
	return
}

func openNatTraversal(tree *server.VyosConfigTree) {
	natT := tree.Get("vpn ipsec nat-traversal")
	if natT == nil {
		tree.Setf("vpn ipsec nat-traversal enable")
	}
}

func restoreIpRuleForMainRouteTable() {
	bash := utils.Bash{
		Command: fmt.Sprintf("ip rule list | grep 32766"),
	}
	ret, out, _, err := bash.RunWithReturn()
	if ret != 0 || err != nil || out == "" {
		bash := utils.Bash{
			Command: fmt.Sprintf("ip rule add from all table main pref 32766"),
		}
		_, _, _, err := bash.RunWithReturn()
		utils.PanicOnError(err)
	}
}

func deleteIPsec(tree *server.VyosConfigTree, info ipsecInfo) {

	tree.Deletef("vpn ipsec ike-group %s", info.Uuid)
	tree.Deletef("vpn ipsec esp-group %s", info.Uuid)
	tree.Deletef("vpn ipsec site-to-site peer %s", info.PeerAddress)
	/* --------------
	   note: tree.Delete("vpn ipsec") will stop the ipsec process, and then delete the
	   ip rule "from all table main pref 32766", this will cause the protocol packets of
	   the ipsec removal sa to not be sent out.
	   -----------------
	*/
	ipsec := tree.Get("vpn ipsec site-to-site peer")
	if ipsec == nil || ipsec.Size() == 0 {
		// no any ipsec connection, delete ipsec related rules
		tree.Delete("vpn ipsec")
	}
}

func updateIPsecConnectionState(tree *server.VyosConfigTree, info ipsecInfo) {
	if info.State == ipsecState_disable {
		for i, _ := range info.PeerCidrs {
			tree.Setf("vpn ipsec site-to-site peer %v tunnel %v disable", info.PeerAddress, i+1)
		}
	} else if info.State == ipsecState_enable {
		for i, _ := range info.PeerCidrs {
			tree.Deletef("vpn ipsec site-to-site peer %v tunnel %v disable", info.PeerAddress, i+1)
		}
	}
	tree.Apply(false)
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
	/* doesn't running in ut */
	if utils.IsRuingUT() {
		return
	}

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

type ipsecVyos struct {
}

func (driver *ipsecVyos) DriverType() string {
	return ipsec_driver_vyos
}

func getPeerConns(ipsec *ipsecInfo) []string {
	var conns []string
	tunnelNo := 1
	for _, _ = range ipsec.LocalCidrs {
		for _, _ = range ipsec.PeerCidrs {
			conns = append(conns, fmt.Sprintf("peer-%s-tunnel-%d", ipsec.PeerAddress, tunnelNo))
			tunnelNo++
		}
	}
	return conns
}

func ipsecDownConns(ipsec *ipsecInfo) {
	conns := getPeerConns(ipsec)
	for _, conn := range conns {
		log.Infof(fmt.Sprintf("TEMP: ipsecDownConns %s", conn))
		ipsecConnDown(conn)
	}
}

func (driver *ipsecVyos) GetIpsecLog(cmd *getIPsecLogCmd) string {
	return "please upgrade ipsec to get log"
}

func (driver *ipsecVyos) ExistConnWorking() bool {
	if exist, _ := utils.PathExists(ipsec_vyos_path_cfg); !exist {
		return false
	}
	contentsByte, _ := ioutil.ReadFile(ipsec_vyos_path_cfg)
	ret := regexp.MustCompile(`\nconn peer-`).FindStringSubmatch(string(contentsByte))
	if len(ret) != 0 {
		return true
	}

	return false
}

func (driver *ipsecVyos) CreateIpsecConns(cmd *createIPsecCmd) error {
	/* use vyos cli to config ipsec */
	AutoRestartVpn = cmd.AutoRestartVpn

	tree := server.GenVyosConfigTree()
	for _, info := range cmd.Infos {
		createIPsec(tree, info)
	}
	openNatTraversal(tree)
	tree.Apply(false)
	go restartVpnAfterConfig()
	return nil
}

func (driver *ipsecVyos) DeleteIpsecConns(cmd *deleteIPsecCmd) error {
	/* use vyos cli to config ipsec */
	tree := server.GenVyosConfigTree()
	for _, info := range cmd.Infos {
		ipsecDownConns(&info)
		deleteIPsec(tree, info)
	}
	tree.Apply(false)
	restoreIpRuleForMainRouteTable()
	return nil
}

func (driver *ipsecVyos) ModifyIpsecConns(cmd *updateIPsecCmd) error {

	tree := server.GenVyosConfigTree()

	for _, conf := range cmd.Infos {
		for _, item := range conf.ModifiedItems {
			if item == "State" {
				updateIPsecConnectionState(tree, conf)
			} else {
				return errors.New("not support modify ipsec config")
			}
		}
	}

	tree.Apply(false)
	restoreIpRuleForMainRouteTable()
	return nil
}

func (driver *ipsecVyos) SyncIpsecConns(cmd *syncIPsecCmd) error {
	/* use vyos cli to config ipsec */
	AutoRestartVpn = cmd.AutoRestartVpn

	tree := server.GenVyosConfigTree()
	for _, info := range cmd.Infos {
		createIPsec(tree, info)
	}
	openNatTraversal(tree)
	tree.Apply(false)
	go restartVpnAfterConfig()

	return nil
}
