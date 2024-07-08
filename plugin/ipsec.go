package plugin

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	log "github.com/sirupsen/logrus"
)

const (
	CREATE_IPSEC_CONNECTION = "/vyos/createipsecconnection"
	DELETE_IPSEC_CONNECTION = "/vyos/deleteipsecconnection"
	SYNC_IPSEC_CONNECTION   = "/vyos/syncipsecconnection"
	UPDATE_IPSEC_CONNECTION = "/vyos/updateipsecconnection"
	UPDATE_IPSEC_VERSION    = "/vyos/updateipsecversion"
	GET_IPSEC_LOG           = "/vyos/getipseclog"

	IPSecInfoMaxSize = 256

	/* because strongswan origin rekey will fail with aliyun ipsec vpn,
	   a work around method is to restart the vpn before the rekey happened */
	IPSecIkeRekeyInterval       = 86400 /*  24 * 3600 seconds */
	IPSecIkeRekeyIntervalMargin = 600   /* restart the vpn 10 mins before rekey */
	IPSecRestartInterval        = IPSecIkeRekeyInterval - IPSecIkeRekeyIntervalMargin

	ipsecAddressGroup = "ipsec-group"
	ipsecGroupTemp    = "ipsec-group-tmp"
	ipsecGroupType    = "hash:ip"

	ipsecState_disable = "Disabled"
	ipsecState_enable  = "Enabled"

	strongswanVersion_5_9_4           = "5.9.4"
	ipsec_driver_strongswan_withipsec = "strongswan_withipsec"
	ipsec_driver_vyos                 = "vyos"
	ipsec_strongswan_upgrade_cmd      = "upgrade.sh"
	ipsec_path_version                = "/usr/local/etc/ipsec.version"
	ipsec_vyos_path_cfg               = "/etc/ipsec.conf"
	ipsec_vyos_path_log               = "/var/log/charon.log"
)

var (
	AutoRestartVpn           = false
	AutoRestartThreadCreated = false
)

func getIpsecStrongSWanDataPath() string {
	return  filepath.Join(utils.GetZvrRootPath(), "data/upgrade/strongswan/")
}

func getHaIpsecScript() string {
	return  filepath.Join(utils.GetZvrRootPath(), "keepalived/script/ipsec.sh")
}

func getIpsecTempScript() string {
	return  filepath.Join(utils.GetZvrRootPath(), "keepalived/temp/ipsec.sh")
}

type ipsecInfo struct {
	Uuid                      string   `json:"uuid"`
	State                     string   `json:"state"`
	LocalCidrs                []string `json:"localCidrs"`
	PeerAddress               string   `json:"peerAddress"`
	LocalId                   string   `json:"localId"`
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
	IkeVersion                string   `json:"ikeVersion"`
	IdType                    string   `json:"idType"`
	IkeLifeTime               int      `json:"ikeLifeTime"`
	LifeTime                  int      `json:"lifeTime"`
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

type updateIPsecCmd struct {
	Infos []ipsecInfo `json:"infos"`
}

type getIPsecLogCmd struct {
	Lines int `json:"lines"`
}

type getIPsecLogRsp struct {
	IpsecLog string `json:"ipsecLog"`
}

type syncIPsecRsp struct {
	DownIpsecConns []string `json:"downIpsecConns"`
}

type updateIpsecVersionCmd struct {
	Infos          []ipsecInfo `json:"infos"`
	AutoRestartVpn bool        `json:"autoRestartVpn"`
	Version        string      `json:"targetVersion"`
}

var ipsecMap map[string]ipsecInfo

func writeIpsecHaScript(enable bool) {
	if !utils.IsHaEnabled() {
		return
	}

	if enable {
		err := utils.CopyFile(getIpsecTempScript(), getHaIpsecScript())
		utils.PanicOnError(err)
	} else {
		conent := "echo 'no ipsec configured'"
		err := os.WriteFile(getHaIpsecScript(), []byte(conent), 0755)
		utils.PanicOnError(err)
	}
}

func syncIpSecRulesByIptables() {
	var (
		snatRules   []*utils.IpTableRule
		filterRules []*utils.IpTableRule
		err         error
	)
	table := utils.NewIpTables(utils.FirewallTable)
	natTable := utils.NewIpTables(utils.NatTable)

	table.RemoveIpTableRuleByComments(utils.IpsecRuleComment)
	natTable.RemoveIpTableRuleByComments(utils.IpsecRuleComment)

	ipsetGroup := utils.NewIPSet(ipsecAddressGroup, ipsecGroupType)
	if !ipsetGroup.IsExist() {
		err = ipsetGroup.Create()
		utils.PanicOnError(err)
	}
	ipsetGroupTemp := utils.NewIPSet(ipsecGroupTemp, ipsecGroupType)
	err = ipsetGroupTemp.Create()
	utils.PanicOnError(err)

	vipNicNameMap := make(map[string]string)
	for _, info := range ipsecMap {
		if _, ok := vipNicNameMap[info.Vip]; ok {
			continue
		}
		nicName, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)
		vipNicNameMap[info.Vip] = nicName
	}

	for _, info := range ipsecMap {
		nicName, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)

		rule := utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
		rule.SetProto(utils.IPTABLES_PROTO_UDP).SetDstPort("500").SetSrcIpset(ipsecAddressGroup)
		filterRules = append(filterRules, rule)

		rule = utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
		rule.SetProto(utils.IPTABLES_PROTO_UDP).SetDstPort("4500").SetSrcIpset(ipsecAddressGroup)
		filterRules = append(filterRules, rule)

		rule = utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
		rule.SetProto(utils.IPTABLES_PROTO_ESP).SetSrcIpset(ipsecAddressGroup)
		filterRules = append(filterRules, rule)

		rule = utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
		rule.SetProto(utils.IPTABLES_PROTO_AH).SetSrcIpset(ipsecAddressGroup)
		filterRules = append(filterRules, rule)

		err = ipsetGroupTemp.AddMember([]string{info.PeerAddress})
		utils.PanicOnError(err)
	}

	for _, info := range ipsecMap {
		nicname, _ := vipNicNameMap[info.Vip]
		for _, remoteCidr := range info.PeerCidrs {
			rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_IN))
			rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
			rule.SetSrcIp(remoteCidr).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
			filterRules = append(filterRules, rule)

			rule = utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
			rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
			rule.SetSrcIp(remoteCidr).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
			filterRules = append(filterRules, rule)
		}

		/* nat rule */
		for _, srcCidr := range info.LocalCidrs {
			for _, remoteCidr := range info.PeerCidrs {
				rule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
				rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpsecRuleComment)
				rule.SetSrcIp(srcCidr).SetDstIp(remoteCidr).SetOutNic(nicname)
				snatRules = append(snatRules, rule)
			}
		}
	}

	table.AddIpTableRules(filterRules)
	if err := table.Apply(); err != nil {
		log.Warnf("ipsec add firewall rule failed %v", err)
		utils.PanicOnError(err)
	}

	natTable.AddIpTableRules(snatRules)
	if err := natTable.Apply(); err != nil {
		log.Warnf("ipsec add nat rule failed %v", err)
		utils.PanicOnError(err)
	}

	_ = ipsetGroupTemp.Swap(ipsetGroup)
	err = ipsetGroupTemp.Destroy()
	utils.PanicOnError(err)
}

func setIPSecRule(tree *server.VyosConfigTree, info *ipsecInfo) {
	nicname, err := utils.GetNicNameByMac(info.PublicNic)
	utils.PanicOnError(err)

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
	return
}

func delIPSecRule(tree *server.VyosConfigTree, info *ipsecInfo) {
	nicname, err := utils.GetNicNameByMac(info.PublicNic)
	utils.PanicOnError(err)

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

	if info.ExcludeSnat {
		for _, localCidr := range info.LocalCidrs {
			for _, remoteCidr := range info.PeerCidrs {
				des = fmt.Sprintf("ipsec-%s-%s-%s", info.Uuid, localCidr, remoteCidr)
				if r := tree.FindSnatRuleDescription(des); r != nil {
					r.Delete()
				}
			}
		}
	}

	if !ipsecVerMgr.currentDriver.ExistConnWorking() {
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

		tree.Deletef("firewall group address-group %s", ipsecAddressGroup)
	}

}

func createIPsecConnection(cmd *createIPsecCmd) interface{} {
	for _, info := range cmd.Infos {
		ipsecMap[info.Uuid] = info
	}

	/* add ipsec iptables rule */
	if utils.IsSkipVyosIptables() {
		syncIpSecRulesByIptables()
	} else {
		tree := server.GenVyosConfigTree()
		for _, info := range cmd.Infos {
			setIPSecRule(tree, &info)
		}
		tree.Apply(false)
	}

	ipsecVerMgr.currentDriver.CreateIpsecConns(cmd)

	writeIpsecHaScript(true)

	return nil
}

func syncIPsecConnection(cmd *syncIPsecCmd) interface{} {
	for _, info := range cmd.Infos {
		ipsecMap[info.Uuid] = info
	}

	/* add ipsec iptables rule */
	if utils.IsSkipVyosIptables() {
		syncIpSecRulesByIptables()
	} else {
		tree := server.GenVyosConfigTree()
		for _, info := range cmd.Infos {
			setIPSecRule(tree, &info)
		}
		tree.Apply(false)
	}

	DownIpsecConns := ipsecVerMgr.currentDriver.SyncIpsecConns(cmd)

	if len(ipsecMap) > 0 {
		writeIpsecHaScript(true)
	} else {
		writeIpsecHaScript(false)
	}

	return syncIPsecRsp{DownIpsecConns: DownIpsecConns}
}

func deleteIPsecConnection(cmd *deleteIPsecCmd) interface{} {
	for _, info := range cmd.Infos {
		delete(ipsecMap, info.Uuid)
	}

	ipsecVerMgr.currentDriver.DeleteIpsecConns(cmd)

	if len(ipsecMap) > 0 {
		writeIpsecHaScript(true)
	} else {
		writeIpsecHaScript(false)
	}

	/* del ipsec iptables rule */
	if utils.IsSkipVyosIptables() {
		syncIpSecRulesByIptables()
	} else {
		tree := server.GenVyosConfigTree()
		for _, info := range cmd.Infos {
			delIPSecRule(tree, &info)
		}
		tree.Apply(false)
	}

	return nil
}

func updateIPsecConnection(cmd *updateIPsecCmd) interface{} {

	ipsecVerMgr.currentDriver.ModifyIpsecConns(cmd)

	return nil
}

func getIpsecLog(cmd *getIPsecLogCmd) interface{} {
	return getIPsecLogRsp{IpsecLog: ipsecVerMgr.currentDriver.GetIpsecLog(cmd)}
}

func getIpsecLogHandler(ctx *server.CommandContext) interface{} {
	cmd := &getIPsecLogCmd{}
	ctx.GetCommand(cmd)
	return getIpsecLog(cmd)
}

func createIPsecConnectionHandler(ctx *server.CommandContext) interface{} {
	cmd := &createIPsecCmd{}
	ctx.GetCommand(cmd)
	return createIPsecConnection(cmd)
}

func syncIPsecConnectionHandler(ctx *server.CommandContext) interface{} {
	cmd := &syncIPsecCmd{}
	ctx.GetCommand(cmd)
	return syncIPsecConnection(cmd)
}

func deleteIPsecConnectionHandler(ctx *server.CommandContext) interface{} {
	cmd := &deleteIPsecCmd{}
	ctx.GetCommand(cmd)
	return deleteIPsecConnection(cmd)
}

func updateIPsecConnectionHandler(ctx *server.CommandContext) interface{} {
	cmd := &updateIPsecCmd{}
	ctx.GetCommand(cmd)
	return updateIPsecConnection(cmd)
}

func updateIPsecVersionHandler(ctx *server.CommandContext) interface{} {
	cmd := &updateIpsecVersionCmd{}
	ctx.GetCommand(cmd)
	err := updateIpsecVersion(cmd)
	if err != nil {
		panic(err)
	}
	return nil
}

type ipsecVersionMgr struct {
	currentVersion  string
	currentDriver   ipsecDriver
	latestVersion   string
	supportVersions []string
	useConfig       bool
}

type ipsecDriver interface {
	DriverType() string
	ExistConnWorking() bool
	CreateIpsecConns(cmd *createIPsecCmd) error
	DeleteIpsecConns(cmd *deleteIPsecCmd) error
	ModifyIpsecConns(cmd *updateIPsecCmd) error
	SyncIpsecConns(cmd *syncIPsecCmd) []string
	GetIpsecLog(cmd *getIPsecLogCmd) string
}

var (
	ipsecVerMgr     = &ipsecVersionMgr{}
	ipsecDriverList = map[string]ipsecDriver{}
)

func getStrongswanSoftwareVersion() (string, error) {
	bash := &utils.Bash{Command: ipsecVersion, Sudo: true}
	_, out, _, err := bash.RunWithReturn()
	if err != nil {
		return "", errors.New("get ipsec version failed, " + err.Error())
	}

	compile := regexp.MustCompile(`U([\d]+.[\d]+.[\d]+)`)
	versionInfo := compile.FindStringSubmatch(out)
	if len(versionInfo) > 1 {
		return versionInfo[1], nil
	}
	return "", errors.New("get ipsec version failed")
}

/*
   the ipsec version that comes with vyos:
      vyos117=4.5.2, vyos12=5.7.2
*/
func updateOriginVersion(version string) error {
	log.Infof("TEMP: updateOriginVersion for version=%s.", version)

	originPath := filepath.Join(getIpsecStrongSWanDataPath(), "origin")
	if exist, _ := utils.PathExists(originPath); !exist {
		return errors.New("no origin version in " + getIpsecStrongSWanDataPath())
	}

	versionPath := filepath.Join(getIpsecStrongSWanDataPath(), version)
	if exist, _ := utils.PathExists(versionPath); !exist {
		if err := os.MkdirAll(versionPath, 0755); err != nil {
			return err
		}

		log.Infof("TEMP: updateOriginVersion create origin dir %s.", versionPath)
	}

	if err := utils.CopyFile(filepath.Join(originPath, ipsec_strongswan_upgrade_cmd),
		filepath.Join(versionPath, ipsec_strongswan_upgrade_cmd)); err != nil {
		return err
	}

	return nil
}

func getCurrentVersionInuse() (string, error) {

	version, err := getStrongswanSoftwareVersion()
	if err != nil {
		return "", err
	}

	if isOriginVersion(version) {
		if err = updateOriginVersion(version); err != nil {
			return "", err
		}
	}

	log.Infof("TEMP: getCurrentVersionInuse version=%s.", version)
	return version, nil
}

func versionInSupport(version string) bool {
	for _, v := range ipsecVerMgr.supportVersions {
		if v == version {
			return true
		}
	}
	return false
}

func isOriginVersion(version string) bool {
	if _, ret := utils.CompareVersion(version, strongswanVersion_5_9_4); ret < 0 {
		return true
	}

	return false
}

func getVersionSupport() []string {
	var supports []string
	if exist, _ := utils.PathExists(getIpsecStrongSWanDataPath()); !exist {
		return supports
	}
	dir, err := ioutil.ReadDir(getIpsecStrongSWanDataPath())
	if err != nil {
		return supports
	}

	for _, fi := range dir {
		name := fi.Name()
		if !fi.IsDir() || name == "origin" {
			continue
		}

		if utils.ValidVersionString(name) { // 目录, 递归遍历
			if isOriginVersion(name) {
				if err = updateOriginVersion(name); err != nil {
					//
					log.Errorf("update origin version file err: %s.", err.Error())
				}
			}

			supports = append(supports, name)
			os.Chmod(filepath.Join(getIpsecStrongSWanDataPath(), name, ipsec_strongswan_upgrade_cmd), 0777)
		}
	}

	sort.Slice(supports, func(i, j int) bool {
		if _, ret := utils.CompareVersion(supports[i], supports[j]); ret < 0 {
			return true
		}
		return false
	})
	return supports
}

func getIpsecDriver(version string) string {
	if utils.Vyos_version == utils.VYOS_1_1_7 || utils.Vyos_version == utils.VYOS_1_2 {
		if _, ret := utils.CompareVersion(version, strongswanVersion_5_9_4); ret >= 0 {
			return ipsec_driver_strongswan_withipsec
		} else {
			return ipsec_driver_vyos
		}
	}

	return ipsec_driver_vyos
}

func upDownStrongswanSoftware(version string, down bool) error {
	var err error

	defer func() {
		if err != nil {
			upDownStrongswanSoftware(version, !down)
		}
	}()

	upgradePath := filepath.Join(getIpsecStrongSWanDataPath(), version, ipsec_strongswan_upgrade_cmd)
	if exist, _ := utils.PathExists(upgradePath); !exist {
		return fmt.Errorf("upgrade.sh for strongswan version %s not existed", version)
	}

	downOpt := ""
	if down {
		downOpt = " -d"
	}

	b := utils.Bash{
		Command:  upgradePath + downOpt,
		Sudo:     true,
		Timeout:  60,
		IsScript: true,
	}
	err = b.Run()
	return err
}

func updateCurrentVersion(currentVersion string, useConfig bool) error {
	if useConfig {
		if err := updateIpsecVersionConfig(currentVersion); err != nil {
			return err
		}
	}
	ipsecVerMgr.useConfig = useConfig

	ipsecVerMgr.currentVersion = currentVersion
	driverName := getIpsecDriver(currentVersion)
	if driverName != ipsecVerMgr.currentDriver.DriverType() {
		ipsecVerMgr.currentDriver = ipsecDriverList[driverName]
	}
	return nil
}

func autoUpgradeStrongswan() error {
	var err error
	if ipsecVerMgr.latestVersion == "" ||
		ipsecVerMgr.currentVersion == ipsecVerMgr.latestVersion {
		return nil
	}

	if ipsecVerMgr.currentDriver.ExistConnWorking() {
		return nil
	}

	if utils.Kernel_version == utils.Kernel_3_13_11 {
		log.Errorf("current vyos kernel [%s] not support upgrade strongswan", utils.Kernel_version)
		return err
	}

	currentVersion := ipsecVerMgr.currentVersion
	if err = upDownStrongswanSoftware(currentVersion, true); err != nil {
		return err
	}

	defer func(v string) {
		if err != nil {
			upDownStrongswanSoftware(v, false)
		}
	}(currentVersion)

	if err = updateCurrentVersion(ipsecVerMgr.latestVersion, false); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			updateCurrentVersion(currentVersion, false)
		}
	}()

	if err = upDownStrongswanSoftware(ipsecVerMgr.currentVersion, false); err != nil {
		return err
	}

	log.Infof("auto upgrade strongswan from %s to %s, current driver %s.",
		currentVersion, ipsecVerMgr.currentVersion, ipsecVerMgr.currentDriver.DriverType())

	return nil
}

/* 手动升级、降级：
    1、删除当前版本 ipsec配置；
	2、降级当前版本软件
    3、修改内存版本信息
	4、升级指定版本软件
	5、创建指定版本 ipsec配置
*/
func updateIpsecVersion(cmd *updateIpsecVersionCmd) error {
	if utils.Kernel_version == utils.Kernel_3_13_11 {
		return fmt.Errorf("current vyos kernel [%s] not support upgrade strongswan", utils.Kernel_version)
	}

	log.Infof("TEMP: start update strongswan version from %s to %s.",
		ipsecVerMgr.currentVersion, cmd.Version)
	if cmd.Version == ipsecVerMgr.currentVersion {
		return nil
	}

	if !versionInSupport(cmd.Version) {
		return fmt.Errorf("version %s is not support", cmd.Version)
	}

	//create origin ipsec upgrade dir
	_, err := getCurrentVersionInuse()
	if err != nil {
		return err
	}

	err = ipsecVerMgr.currentDriver.DeleteIpsecConns(&deleteIPsecCmd{cmd.Infos})
	if err != nil {
		return err
	}
	// wait for strongswan to notify the peer to delete connections and ipsec config(vyos).
	time.Sleep(time.Second)

	defer func(driver ipsecDriver) {
		if err != nil {
			driver.CreateIpsecConns(&createIPsecCmd{Infos: cmd.Infos, AutoRestartVpn: cmd.AutoRestartVpn})
		}
	}(ipsecVerMgr.currentDriver)

	currentVersion := ipsecVerMgr.currentVersion
	useConfig := ipsecVerMgr.useConfig
	if err = upDownStrongswanSoftware(currentVersion, true); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			upDownStrongswanSoftware(currentVersion, false)
		}
	}()

	if err = updateCurrentVersion(cmd.Version, true); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			updateCurrentVersion(currentVersion, useConfig)
		}
	}()

	if err = upDownStrongswanSoftware(ipsecVerMgr.currentVersion, false); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			upDownStrongswanSoftware(ipsecVerMgr.currentVersion, true)
		}
	}()

	err = ipsecVerMgr.currentDriver.CreateIpsecConns(&createIPsecCmd{Infos: cmd.Infos, AutoRestartVpn: cmd.AutoRestartVpn})
	if err != nil {
		return err
	}

	log.Infof("success update strongswan version from %s to %s, current driver=%s.",
		currentVersion, ipsecVerMgr.currentVersion, ipsecVerMgr.currentDriver.DriverType())
	return nil
}

func getIpsecVersionUserConfig() (string, error) {

	data, err := ioutil.ReadFile(ipsec_path_version)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func updateIpsecVersionConfig(version string) error {
	return utils.WriteFile(ipsec_path_version, version)
}

func checkIpsecCurrentVersion() (err error, isUserConfig bool) {
	var version string
	if exist, _ := utils.PathExists(ipsec_path_version); !exist {
		return nil, false
	}

	version, err = getIpsecVersionUserConfig()
	if err != nil {
		return err, false
	}

	if ipsecVerMgr.currentVersion != version {
		errInfo := fmt.Sprintf("the current ipsec version(%s) is inconsistent with the user configuration(%s)",
			ipsecVerMgr.currentVersion, version)

		log.Errorf(errInfo)
		return errors.New(errInfo), false
	}

	return nil, true
}

func IpsecInit() error {
	// currently, supports vyos and strongswan(with ipsec cli) driver.
	ipsecDriverList = make(map[string]ipsecDriver)
	ipsecDriverList[ipsec_driver_strongswan_withipsec] = &ipsecStrongSWan{}
	ipsecDriverList[ipsec_driver_vyos] = &ipsecVyos{}

	version, err := getCurrentVersionInuse()
	if err != nil {
		return err
	}

	driverName := getIpsecDriver(version)
	if driver, ok := ipsecDriverList[driverName]; ok {
		ipsecVerMgr.currentVersion = version
		ipsecVerMgr.currentDriver = driver
	} else {
		return errors.New("no ipsec driver for " + driverName)
	}

	supportVersions := getVersionSupport()
	if len(supportVersions) == 0 {
		supportVersions = append(supportVersions, version)
	}

	ipsecVerMgr.supportVersions = supportVersions
	ipsecVerMgr.latestVersion = supportVersions[len(supportVersions)-1]

	log.Infof("strongswan version info: current version %s, current driver %s, latest version %s.",
		ipsecVerMgr.currentVersion, ipsecVerMgr.currentDriver.DriverType(), ipsecVerMgr.latestVersion)

	err, useConfig := checkIpsecCurrentVersion()
	if err != nil {
		return err
	}
	ipsecVerMgr.useConfig = useConfig
	if !useConfig {
		// check and upgrade
		autoUpgradeStrongswan()
	}

	return nil
}

func GetIpsecServiceStatus() *ServiceStatus {
	return &ServiceStatus{"ipsec",
		ipsecVerMgr.currentVersion,
		ipsecVerMgr.latestVersion,
		ipsecVerMgr.supportVersions}
}

func GetIpsecVersionInfo() (string, string) {
	return ipsecVerMgr.currentVersion, ipsecVerMgr.latestVersion
}

func IPsecEntryPoint() {
	ipsecMap = make(map[string]ipsecInfo, IPSecInfoMaxSize)
	server.RegisterAsyncCommandHandler(CREATE_IPSEC_CONNECTION, server.VyosLock(createIPsecConnectionHandler))
	server.RegisterAsyncCommandHandler(DELETE_IPSEC_CONNECTION, server.VyosLock(deleteIPsecConnectionHandler))
	server.RegisterAsyncCommandHandler(SYNC_IPSEC_CONNECTION, server.VyosLock(syncIPsecConnectionHandler))
	server.RegisterAsyncCommandHandler(UPDATE_IPSEC_CONNECTION, server.VyosLock(updateIPsecConnectionHandler))
	server.RegisterAsyncCommandHandler(UPDATE_IPSEC_VERSION, server.VyosLock(updateIPsecVersionHandler))
	server.RegisterAsyncCommandHandler(GET_IPSEC_LOG, server.VyosLock(getIpsecLogHandler))
}
