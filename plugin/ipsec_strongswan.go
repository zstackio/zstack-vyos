package plugin

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"text/template"

	log "github.com/Sirupsen/logrus"
	"github.com/zstackio/zstack-vyos/utils"
)

const (
	ipsecSecretFormat = "%s %s : PSK %s"
	ipsecConfFormat   = `
conn {{.ConnName}}
    left={{.Left}}
    {{- if ne .Right ""}}   
    right={{.Right}}
    {{- end}}
    leftsubnet={{.Leftsubnet}}
    rightsubnet={{.Rightsubnet}}
    {{- if ne .Auto ""}}
    auto={{.Auto}}
    {{- end}}	
    {{- if ne .Ikelifetime ""}}
    ikelifetime={{.Ikelifetime}}
    {{- end}}
    {{- if ne .Lifetime ""}}
    lifetime={{.Lifetime}}
    {{- end}}
    {{- if ne .Margintime ""}}
    margintime={{.Margintime}}
    {{- end}}
    {{- if ne .Authby ""}}
    authby={{.Authby}}
    {{- end}}
    {{- if ne .Keyexchange ""}}
    keyexchange={{.Keyexchange}}
    {{- end}}
    {{- if ne .Ike ""}}
    ike={{.Ike}}
    {{- end}}
    {{- if ne .Esp ""}}
    esp={{.Esp}}
    {{- end}}
    {{- if ne .Dpdaction ""}}
    dpdaction={{.Dpdaction}}
    {{- end}}    
    {{- if ne .Dpddelay ""}}
    dpddelay={{.Dpddelay}}
    {{- end}}
    {{- if ne .Keyingtries ""}}
    keyingtries={{.Keyingtries}}
    {{- end}}
    {{- if ne .Leftid ""}}
    leftid={{.Leftid}}
    {{- end}}
    {{- if ne .Rightid ""}}
    rightid={{.Rightid}}
    {{- end}}
    {{- if ne .Aggressive ""}}
    aggressive={{.Aggressive}}
    {{- end}}
    mobike=no
    `

	// 新版本strongswan路径
	ipsec_path_bin_ipsec    = "/usr/local/sbin/ipsec"
	ipsec_path_cfg_ipsecdir = "/usr/local/etc/ipsec.d/"
	//ipsec_path_upgrade      = "/usr/local/etc/ipsec.upgrade"

	ipsecConnDownCmd      = "ipsec down " // 空格不能删
	ipsecConnUpCmd        = "ipsec up "   // 空格不能删
	ipsecReloadConfCmd    = "ipsec reload"
	ipsecReloadSecretsCmd = "ipsec rereadsecrets"
	ipsecStatus           = "ipsec status "
	ipsecVersion          = "ipsec version "

	idtype_ip       = "ip"
	idtype_name     = "name"
	idtype_fqdn     = "fqdn"
	idtype_userfqdn = "userfqdn"
)

type ipsecConf struct {
	ConnName    string
	Left        string
	Right       string
	IdType      string
	Leftid      string
	Rightid     string
	Ikelifetime string
	Lifetime    string
	Authby      string
	Keyexchange string
	Ike         string
	Esp         string
	Leftsubnet  string
	Rightsubnet string
	Auto        string
	Dpdaction   string
	Dpddelay    string
	Keyingtries string
	Aggressive  string
	EncapMode   string
	Secret      string
	Margintime  string
}

var (
	ipsecNativeFlag         = false
	strongswanVersion_4_5_2 = "origin"

	strongswanVersion = strongswanVersion_4_5_2
	dhGroupMap        = map[string]string{
		"2":          "modp1024",
		"5":          "modp1536",
		"14":         "modp2048",
		"15":         "modp3072",
		"16":         "modp4096",
		"17":         "modp6144",
		"18":         "modp8192",
		"19":         "ecp256",
		"20":         "ecp384",
		"21":         "ecp521",
		"22":         "modp1024s160",
		"23":         "modp2048s224",
		"24":         "modp2048s256",
		"25":         "ecp192",
		"26":         "ecp224",
		"dh-group2":  "modp1024",
		"dh-group5":  "modp1536",
		"dh-group14": "modp2048",
		"dh-group15": "modp3072",
		"dh-group16": "modp4096",
		"dh-group17": "modp6144",
		"dh-group18": "modp8192",
		"dh-group19": "ecp256",
		"dh-group20": "ecp384",
		"dh-group21": "ecp521",
		"dh-group22": "modp1024s160",
		"dh-group23": "modp2048s224",
		"dh-group24": "modp2048s256",
		"dh-group25": "ecp192",
		"dh-group26": "ecp224",
	}
)

func useStrongswan_5_9_4() bool {
	return strongswanVersion == strongswanVersion_5_9_4
}

func useStrongswanDriver() bool {
	return strongswanVersion >= strongswanVersion_5_9_4
}

func getIpsecConfFile(uuid string) string {
	return ipsec_path_cfg_ipsecdir + uuid + ".conf"
}

func getIpsecSecretFile(uuid string) string {
	return ipsec_path_cfg_ipsecdir + uuid + ".secrets"
}

func getPrefixByIdType(idType string) string {
	if idType == idtype_fqdn || idType == idtype_name {
		return "@"
	} else if idType == idtype_userfqdn {
		return "@@"
	}
	return ""
}

func getNativeConf(ipsecMsg *ipsecInfo) (error, *ipsecConf) {

	conf := &ipsecConf{}
	conf.ConnName = ipsecMsg.Uuid
	conf.Authby = ipsecMsg.AuthMode
	conf.Secret = ipsecMsg.AuthKey
	conf.Keyexchange = ipsecMsg.IkeVersion
	conf.Left = ipsecMsg.Vip
	if ipsecMsg.PeerAddress != "" {
		conf.Right = ipsecMsg.PeerAddress
	} else {
		conf.Right = "%any"
	}

	conf.EncapMode = ipsecMsg.PolicyMode

	if regularDH, ok := dhGroupMap[strconv.Itoa(ipsecMsg.IkeDhGroup)]; ok {
		conf.Ike = ipsecMsg.IkeEncryptionAlgorithm + "-" + ipsecMsg.IkeAuthAlgorithm + "-" + regularDH + "!"
	} else {
		conf.Ike = ipsecMsg.IkeEncryptionAlgorithm + "-" + ipsecMsg.IkeAuthAlgorithm + "!"
	}

	if regularDH, ok := dhGroupMap[ipsecMsg.Pfs]; ok {
		conf.Esp = ipsecMsg.PolicyEncryptionAlgorithm + "-" + ipsecMsg.PolicyAuthAlgorithm + "-" + regularDH + "!"
	} else {
		conf.Esp = ipsecMsg.PolicyEncryptionAlgorithm + "-" + ipsecMsg.PolicyAuthAlgorithm + "!"
	}

	conf.IdType = ipsecMsg.IdType
	prefix := getPrefixByIdType(conf.IdType)
	if ipsecMsg.LocalId != "" {
		conf.Leftid = prefix + ipsecMsg.LocalId
	} else {
		conf.Leftid = ipsecMsg.Vip
	}

	if ipsecMsg.RemoteId != "" {
		conf.Rightid = prefix + ipsecMsg.RemoteId
	} else {
		conf.Rightid = ipsecMsg.PeerAddress
	}

	for index, cidr := range ipsecMsg.LocalCidrs {
		if index != 0 {
			conf.Leftsubnet += ","
		}
		conf.Leftsubnet += cidr
	}

	for index, cidr := range ipsecMsg.PeerCidrs {
		if index != 0 {
			conf.Rightsubnet += ","
		}
		conf.Rightsubnet += cidr
	}

	if ipsecMsg.IkeLifeTime > 0 {
		conf.Ikelifetime = strconv.Itoa(ipsecMsg.IkeLifeTime)
	} else {
		conf.Ikelifetime = "86400"
	}

	if ipsecMsg.LifeTime > 0 {
		conf.Lifetime = strconv.Itoa(ipsecMsg.LifeTime)
		conf.Margintime = strconv.Itoa(ipsecMsg.LifeTime / 10)
	} else {
		conf.Lifetime = "3600"
		conf.Margintime = "360"
	}

	// default value
	conf.Aggressive = "no"
	conf.Auto = "start"
	conf.Keyingtries = "%forever"

	conf.Dpddelay = ""
	conf.Dpdaction = "restart"

	return nil, conf
}

func saveIpsecSecret(ipsecCfg *ipsecConf) error {
	prefix := getPrefixByIdType(ipsecCfg.IdType)
	return utils.WriteFile(getIpsecSecretFile(ipsecCfg.ConnName),
		fmt.Sprintf(ipsecSecretFormat, prefix+ipsecCfg.Leftid, prefix+ipsecCfg.Rightid, ipsecCfg.Secret))
}

func removeIpsecSecretCfg(connUuid string) error {
	return utils.SudoRmFile(getIpsecConfFile(connUuid))
}

func getIpsecBackupFile(file string) string {
	return file + "_bak"
}

/*
func saveIpsecConnCfg(ipsecCfg *ipsecConf) error {

	filename := getIpsecConfFile(ipsecCfg.ConnName)

	tmpl, err := template.New(ipsecCfg.ConnName).Parse(ipsecConfFormat)
	if err != nil {
		return err
	}

	var fileConf *os.File
	fileConf, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(filename)
		} else {
			fileConf.Close()
		}
	}()

	if err = tmpl.Execute(fileConf, ipsecCfg); err != nil {
		return err
	}

	return nil
}
*/

func saveIpsecConnCfg(ipsecCfg *ipsecConf) error {

	tmpl, err := template.New(ipsecCfg.ConnName).Parse(ipsecConfFormat)
	if err != nil {
		return err
	}

	var fileConf *os.File
	fileConf, err = ioutil.TempFile("", ipsecCfg.ConnName)
	defer utils.SudoRmFile(fileConf.Name())
	if err != nil {
		return err
	}

	if err = tmpl.Execute(fileConf, ipsecCfg); err != nil {
		return err
	}

	if err = utils.SudoMoveFile(fileConf.Name(), getIpsecConfFile(ipsecCfg.ConnName)); err != nil {
		return err
	}

	return nil
}
func removeIpsecConnCfg(connUuid string) error {
	return utils.SudoRmFile(getIpsecConfFile(connUuid))
}

func ipsecReloadConn() error {
	b := utils.Bash{
		Command: ipsecReloadConfCmd,
		Sudo:    true,
	}
	return b.Run()
}

func ipsecReloadSecret() error {
	b := utils.Bash{
		Command: ipsecReloadSecretsCmd,
		Sudo:    true,
	}
	return b.Run()
}

func ipsecConnDown(connName string) error {
	b := utils.Bash{
		Command: ipsecConnDownCmd + connName,
		Sudo:    true,
		Timeout: 3,
	}
	return b.Run()
}

func ipsecConnUp(connName string) error {
	b := utils.Bash{
		Command: ipsecConnUpCmd + connName,
		Sudo:    true,
	}
	return b.Run()
}

func isIpsecConnUp(connName string) (bool, error) {
	b := utils.Bash{
		Command: ipsecStatus + connName,
		Sudo:    true,
	}

	ret, out, _, err := b.RunWithReturn()
	if ret != 0 || err != nil {
		if err != nil {
			return false, err
		}
		return false, errors.New("bash " + ipsecStatus + connName + "failed")
	}
	// 包括rekeying reauthing installed等状态
	if strings.Contains(out, "1 up") {
		return true, nil
	}

	return false, nil
}

func startIpsec() error {

	b := utils.Bash{
		Command: "pidof starter",
	}
	_, out, _, _ := b.RunWithReturn()
	if out != "" {
		return nil
	}

	b = utils.Bash{
		Command: "ipsec start",
		Sudo:    true,
	}

	if err := b.Run(); err != nil {
		return err
	}

	b = utils.Bash{
		Command: "pidof starter",
	}
	_, out, _, _ = b.RunWithReturn()
	if out == "" {
		return errors.New("start ipsec failed")
	}

	return nil
}

func stopIpsec() error {
	b := utils.Bash{
		Command: "ipsec stop",
		Sudo:    true,
	}

	if err := b.Run(); err != nil {
		return err
	}

	return nil
}

// 文件不存在返回成功
func fileBackup(filename, fileBak string) (error, string) {

	if ok, err := utils.PathExists(filename); err != nil {
		return err, ""
	} else if ok {
		err = utils.SudoMoveFile(filename, fileBak)
		//err = os.Rename(filename, fileBak)
		if err != nil {
			return err, ""
		}
		return nil, fileBak
	}
	return nil, ""
}

func backupIpsecConnCfgAndSecret(cfgUuid string) error {
	var backupError error
	fileCfg := getIpsecConfFile(cfgUuid)
	fileCfgBak := getIpsecBackupFile(fileCfg)

	backupError, fileCfgBak = fileBackup(fileCfg, fileCfgBak)
	if backupError != nil {
		return backupError
	}

	fileSecret := getIpsecSecretFile(cfgUuid)
	fileSecretBak := getIpsecBackupFile(fileSecret)
	backupError, fileSecretBak = fileBackup(fileSecret, fileSecretBak)
	if backupError != nil {
		return backupError
	}

	return nil
}

func restoreIpsecConnCfgAndSecret(cfgUuid string, backupError error, reloadOpt, downOpt bool) error {
	var restoreError error
	fileCfg := getIpsecConfFile(cfgUuid)
	fileCfgBak := getIpsecBackupFile(fileCfg)
	fileSecret := getIpsecSecretFile(cfgUuid)
	fileSecretBak := getIpsecBackupFile(fileSecret)

	if backupError != nil {
		if fileCfgBak != "" {
			restoreError, _ = fileBackup(fileCfgBak, fileCfg)
		}
		if fileSecretBak != "" {
			restoreError, _ = fileBackup(fileSecretBak, fileSecret)
		}
		if reloadOpt {
			ipsecReloadConn()
		}
		if downOpt {
			ipsecConnUp(cfgUuid)
		}
	} else {
		if fileCfgBak != "" {
			utils.SudoRmFile(fileCfgBak)
		}
		if fileSecretBak != "" {
			utils.SudoRmFile(fileSecretBak)
		}
	}
	return restoreError
}

func saveIpsecConnCfgAndSecret(conf *ipsecConf) (error, error) {
	var saveConnCfgError, saveSecretError error
	saveConnCfgError = saveIpsecConnCfg(conf)
	if saveConnCfgError != nil {
		return saveConnCfgError, saveSecretError
	}
	saveSecretError = saveIpsecSecret(conf)
	if saveSecretError != nil {
		return saveConnCfgError, saveSecretError
	}
	return nil, nil
}

func reloadIpsecConnCfgAndSecret(cfgUuid string, restartConnOpt, downOpt, reloadOpt *bool) error {
	var reloadError error
	fileCfg := getIpsecConfFile(cfgUuid)
	fileCfgBak := getIpsecBackupFile(fileCfg)
	if fileCfgBak != "" {
		ipsecConnDown(cfgUuid)
		*downOpt = true
	}
	if reloadError = ipsecReloadConn(); reloadError != nil {
		return reloadError
	}
	*reloadOpt = true
	if reloadError = ipsecReloadSecret(); reloadError != nil {
		return reloadError
	}
	if *restartConnOpt {
		go func() {
			ipsecConnDown(cfgUuid)
			ipsecConnUp(cfgUuid)
		}()
	}
	return nil
}

func modifyIpsecNative(confMsg *ipsecInfo) error {
	downOpt := false
	reloadOpt := false
	restartConnOpt := false
	err, conf := getNativeConf(confMsg) // 转换配置
	if err != nil {
		log.Error(err.Error())
		return err
	}

	// 备份操作 AND 备份失败回滚
	backupError := backupIpsecConnCfgAndSecret(conf.ConnName)
	defer restoreIpsecConnCfgAndSecret(conf.ConnName, backupError, downOpt, reloadOpt)
	if backupError != nil {
		log.Error(backupError.Error())
		return backupError
	}

	// 保存配置 AND 回滚保存操作
	saveConnCfgError, saveSecretError := saveIpsecConnCfgAndSecret(conf)
	restartConnOpt = true
	defer func() {
		if saveConnCfgError != nil {
			removeIpsecConnCfg(conf.ConnName)
		}
		if saveSecretError != nil {
			removeIpsecSecretCfg(conf.ConnName)
		}
	}()
	if saveConnCfgError != nil {
		log.Error(saveConnCfgError.Error())
		return saveConnCfgError
	}
	if saveSecretError != nil {
		log.Error(saveSecretError.Error())
		return saveSecretError
	}

	// 读取配置
	if reloadError := reloadIpsecConnCfgAndSecret(conf.ConnName, &restartConnOpt, &downOpt, &reloadOpt); reloadError != nil {
		return reloadError
	}

	return nil
}

func backupIpsecConfigFile(fileCfg, fileCfgBak, connId string) error {
	var err error
	reloadOpt := false

	err, fileCfgBak = fileBackup(fileCfg, fileCfgBak)
	defer func() {
		// 回退
		if err == nil {
			return
		}
		fileBackup(fileCfgBak, fileCfg)

		if reloadOpt {
			ipsecReloadConn()
		}
	}()
	if err != nil {
		return err
	}
	// fileCfg不存在的情况
	if fileCfgBak == "" {
		return nil
	}

	if err = ipsecReloadConn(); err != nil {
		return err
	}
	reloadOpt = true

	err = ipsecConnDown(connId)
	if err != nil {
		return err
	}

	return nil
}

func updateIpsecStateNative(confMsg *ipsecInfo) error {
	var err error
	fileCfg := getIpsecConfFile(confMsg.Uuid)
	fileCfgBak := getIpsecBackupFile(fileCfg)

	if confMsg.State == ipsecState_disable {
		err = backupIpsecConfigFile(fileCfg, fileCfgBak, confMsg.Uuid)
	} else if confMsg.State == ipsecState_enable {
		err = backupIpsecConfigFile(fileCfgBak, fileCfg, confMsg.Uuid)
	}

	return err
}

func deleteIpsecNative(confMsg *ipsecInfo) error {
	downOpt := false
	reloadOpt := false
	restartConnOpt := false
	// 备份操作 AND 备份失败回滚
	backupError := backupIpsecConnCfgAndSecret(confMsg.Uuid)
	defer restoreIpsecConnCfgAndSecret(confMsg.Uuid, backupError, downOpt, reloadOpt)
	if backupError != nil {
		log.Error(backupError.Error())
		return backupError
	}
	// 读取配置
	if reloadError := reloadIpsecConnCfgAndSecret(confMsg.Uuid, &restartConnOpt, &downOpt, &reloadOpt); reloadError != nil {
		return reloadError
	}

	return nil
}

func initIpsecLogrotate() {
	//  /etc/logrotate.d/charon
	rotateConf := "/var/log/charon.log {\n" +
		"size 50M\n" +
		"rotate 10\n" +
		"compress\n" +
		"copytruncate\n" +
		"notifempty\n" +
		"missingok\n" +
		"}"

	if err := utils.WriteFile("/etc/logrotate.d/charon", rotateConf); err != nil {
		utils.PanicOnError(err)
	}

	return
}

func getIpsecConns() map[string]string {
	connUuids := make(map[string]string)
	files, _ := ioutil.ReadDir(ipsec_path_cfg_ipsecdir)
	for _, f := range files {
		filename := f.Name() // 1234.conf
		fmt.Println(filename)
		fileExt := path.Ext(filename)
		if fileExt == ".conf" || fileExt == ".conf_bak" {
			connUuids[filename[0:(len(filename)-len(fileExt))]] = filename
		}
	}

	return connUuids
}

func ageIpsecConns(conns map[string]string) {
	for id, name := range conns {
		// 包含backup文件
		utils.SudoRmFile(ipsec_path_cfg_ipsecdir + name)
		utils.SudoRmFile(getIpsecSecretFile(id))

		ipsecReloadConn()
		if !strings.Contains(name, "bak") {
			ipsecConnDown(id)
		}
	}
}

type ipsecStrongSWan struct {
}

func (driver *ipsecStrongSWan) DriverType() string {
	return ipsec_driver_strongswan_withipsec
}

func (driver *ipsecStrongSWan) ExistConnWorking() bool {
	if exist, _ := utils.PathExists(ipsec_path_cfg_ipsecdir); !exist {
		return false
	}

	dir, _ := ioutil.ReadDir(ipsec_path_cfg_ipsecdir)
	for _, fi := range dir {
		if strings.HasSuffix(fi.Name(), ".conf") { // 目录, 递归遍历
			return true
		}
	}

	return false
}

func (driver *ipsecStrongSWan) CreateIpsecConns(cmd *createIPsecCmd) error {

	/* use ipsec command to config ipsec */
	if err := startIpsec(); err != nil {
		log.Error("start ipsec daemon err: " + err.Error())
		return nil
	}

	for _, conf := range cmd.Infos {
		if err := modifyIpsecNative(&conf); err != nil {
			log.Error("create ipsec connection err: " + err.Error())
		}
	}

	return nil
}

func (driver *ipsecStrongSWan) DeleteIpsecConns(cmd *deleteIPsecCmd) error {
	for _, conf := range cmd.Infos {
		if err := deleteIpsecNative(&conf); err != nil {
			log.Error("delete ipsec connection err: " + err.Error())
		}
	}
	return nil
}

func (driver *ipsecStrongSWan) ModifyIpsecConns(cmd *updateIPsecCmd) error {

	for _, conf := range cmd.Infos {
		for _, item := range conf.ModifiedItems {
			if item == "State" {
				// 支持状态修改
				if err := updateIpsecStateNative(&conf); err != nil {
					log.Error("update ipsec state err: " + err.Error())
				}

			} else {
				// 支持配置修改
				if err := modifyIpsecNative(&conf); err != nil {
					log.Error("update ipsec connection err: " + err.Error())
				}
			}
		}
	}
	return nil
}

func (driver *ipsecStrongSWan) SyncIpsecConns(cmd *syncIPsecCmd) error {
	if len(cmd.Infos) == 0 {
		stopIpsec()
		return nil
	}

	if err := startIpsec(); err != nil {
		log.Error("start ipsec daemon err: " + err.Error())
		return nil
	}

	for _, info := range cmd.Infos {
		if err := modifyIpsecNative(&info); err != nil {
			log.Error("create ipsec connection err: " + err.Error())
		}
	}
	return nil
}