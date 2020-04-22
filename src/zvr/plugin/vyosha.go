package plugin

import (
	"zvr/server"
	"fmt"
	"zvr/utils"
	log "github.com/Sirupsen/logrus"
	"strings"
	"time"
)

const (
	SET_VYOSHA_PATH = "/enableVyosha"
)

type setVyosHaCmd struct {
	Keepalive int  `json:"keepalive"`
	HeartbeatNic string `json:"heartbeatNic"`
	LocalIp string `json:"localIp"`
	PeerIp string `json:"peerIp"`
	Monitors []string `json:"monitors"`
	Vips []macVipPair `json:"vips"`
	CallbackUrl string `json:"callbackUrl"`
}

type macVipPair struct {
	NicMac string     	`json:"nicMac"`
	NicVip     string  	`json:"nicVip"`
	Netmask     string  	`json:"netmask"`
	Category     string  	`json:"category"`
}

var haStatusCallbackUrl = ""

func setVyosHaHandler(ctx *server.CommandContext) interface{} {
	cmd := &setVyosHaCmd{}
	ctx.GetCommand(cmd)

	heartbeatNicNme, _ := utils.GetNicNameByMac(cmd.HeartbeatNic)
	/* add firewall */
	tree := server.NewParserFromShowConfiguration().Tree
	if utils.IsSkipVyosIptables() {
		rule := utils.NewIptablesRule("vrrp", cmd.PeerIp, "", 0, 0, nil, utils.ACCEPT, utils.VRRPComment)
		utils.InsertFireWallRule(heartbeatNicNme, rule, utils.LOCAL)

		rule = utils.NewNatIptablesRule("vrrp", "", "", 0, 0, nil, utils.RETURN, utils.VRRPComment, "", 0)
		utils.InsertNatRule(rule, utils.POSTROUTING)
	} else {
		des := "Vyos-HA"
		if fr := tree.FindFirewallRuleByDescription(heartbeatNicNme, "local", des); fr == nil {
			tree.SetFirewallOnInterface(heartbeatNicNme, "local",
				"action accept",
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("source address %v", cmd.PeerIp),
				fmt.Sprintf("protocol vrrp"),
			)
		}

		if r := tree.FindSnatRuleDescription(des); r == nil {
			num := tree.SetSnatExclude(
				fmt.Sprintf("protocol vrrp"),
				fmt.Sprintf("outbound-interface %v", heartbeatNicNme),
				fmt.Sprintf("description %v", des),
			)
			if f := tree.FindFirstNotExcludeSNATRule(1); num != 1 && num > f {
				/* there has not been run here never */
				utils.LogError(fmt.Errorf("there is SNAT rule number unexcepted, rule:%v %v",
					tree.Getf("nat source rule %v", num),  tree.Getf("nat source rule %v", f)))
				tree.SwapSnatRule(num, f)
				num = f
			}
			tree.SetSnatWithRuleNumber(num, "exclude")
		}
	}

	pairs := []nicVipPair{}
	for _, p := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(p.NicMac); utils.PanicOnError(err)
		cidr, err := utils.NetmaskToCIDR(p.Netmask); utils.PanicOnError(err)
		pairs = append(pairs, nicVipPair{NicName: nicname, Vip: p.NicVip, Prefix:cidr})

		addSecondaryIpFirewall(nicname, p.NicVip, tree)
	}

	tree.Apply(false)

	/* generate notify script first */
	haStatusCallbackUrl = cmd.CallbackUrl
	addHaNicVipPair(pairs, false)

	if cmd.PeerIp == "" {
		cmd.PeerIp = cmd.LocalIp
	}
	checksum, err := getFileChecksum(KeepalivedConfigFile);utils.PanicOnError(err)
	keepalivedConf := NewKeepalivedConf(heartbeatNicNme, cmd.LocalIp, cmd.PeerIp, cmd.Monitors, cmd.Keepalive)
	keepalivedConf.BuildConf()
	newCheckSum, err := getFileChecksum(KeepalivedConfigFile);utils.PanicOnError(err)
	if newCheckSum != checksum {
		keepalivedConf.RestartKeepalived()
	} else {
		log.Debugf("keepalived configure file unchanged")
	}

	return nil
}

func IsMaster() bool {
	if !utils.IsHaEabled() {
		return true
	}

	return keepAlivedStatus == KeepAlivedStatus_Master
}

type haStatusCallback struct {
	VirtualRouterUuid string     	`json:"virtualRouterUuid"`
	HaStatus     string  	`json:"haStatus"`
}

/*
func postHaStatusToManageNode(status KeepAlivedStatus) {
	cmd := haStatusCallback{VirtualRouterUuid: utils.GetVirtualRouterUuid(), HaStatus: status.string()}
	err := utils.HttpPostForObject(haStatusCallbackUrl, map[string]string{"commandpath": "/vpc/hastatus", }, cmd, nil)
}*/

func getKeepAlivedStatusTask()  {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for  {
		select {
		case <-ticker.C:
		        if utils.IsHaEabled() {
				newHaStatus := getKeepAlivedStatus()
				if newHaStatus == KeepAlivedStatus_Unknown || newHaStatus == keepAlivedStatus {
					continue
				}

				/* there is a situation when zvr write the keepalived notify script,
		           	at the same time keepalived is changing state,
		           	so when zvr detect status change, all script again to make sure no missing config */
				keepAlivedStatus = newHaStatus
				server.VyosLockInterface(callStatusChangeScripts)()
			}
		}
	}
}

func keepAlivedCheckTask()  {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for  {
		select {
		case <-ticker.C:
		        if utils.IsHaEabled() {
				checkKeepalivedRunning()
			}
		}
	}
}

type nicVipPair struct {
	NicName string
	Vip     string
	Prefix  int
}

type vyosNicVipPairs struct {
	pairs []nicVipPair
}

func generateNotityScripts()  {
	/* only vip on management nic will be added in master script and will be deleted in backup script */
	mgmtVip := []nicVipPair{}
	for _, p := range haVipPairs.pairs {
		if utils.IsInManagementCidr(p.Vip) {
			mgmtVip = append(mgmtVip, p)
		}
	}

	keepalivedNofityConf := NewKeepalivedNotifyConf(haVipPairs.pairs, mgmtVip)
	keepalivedNofityConf.CreateMasterScript()
	keepalivedNofityConf.CreateBackupScript()
}

func addHaNicVipPair(pairs []nicVipPair, callscript bool)  {
	count := 0
	for _, p := range pairs {
		found := false
		for _, op := range haVipPairs.pairs {
			if p.NicName == op.NicName && p.Vip == op.Vip {
				found = true
				break
			}
		}

		if !found {
			count ++;
			haVipPairs.pairs = append(haVipPairs.pairs, p)
		}
	}

	generateNotityScripts()

	if callscript {
		callStatusChangeScripts()
	}
}

func removeHaNicVipPair(pairs []nicVipPair)  {
	newPair := []nicVipPair{}
	for _, p := range haVipPairs.pairs {
		found := false
		for _, np := range pairs {
			if p.NicName == np.NicName && p.Vip == np.Vip {
				found = true
				break
			}
		}

		if !found {
			newPair = append(newPair, p)
		}
	}

	if len(newPair) != len(haVipPairs.pairs) {
		haVipPairs.pairs = newPair
		generateNotityScripts()
	}
}

func mountTmpFolderAsTmpfs()  {
	/* mount /tmp as tmpfs */
	b := utils.Bash{
		Command: "sudo mount | grep '/tmp'",
	}
	_, o, _, _ := b.RunWithReturn()
	o = strings.Trim(o, " \n\t")
	if o == "" {
		b := utils.Bash{
			Command: "sudo mount -t tmpfs -o size=64M tmpfs /tmp",
		}
		b.Run()
	}
}

func InitHaNicState()  {
	mountTmpFolderAsTmpfs()

	if !utils.IsHaEabled() {
		return
	}

	/* if ha is enable, shutdown all interface except eth0 */
	cmds := []string{}
	nics, _ := utils.GetAllNics()
	for _, nic := range nics {
		if nic.Name == "eth0" {
			continue
		}

		if strings.Contains(nic.Name, "eth") {
			cmds = append(cmds, fmt.Sprintf("ip link set dev %v down", nic.Name))
		}
	}

	cmds = append(cmds, fmt.Sprintf("sudo sysctl -w net.ipv4.ip_nonlocal_bind=1"))
	b := utils.Bash{
		Command: strings.Join(cmds, "\n"),
	}

	b.Run()
	b.PanicIfError()
}

var haVipPairs  vyosNicVipPairs
func init() {
	haVipPairs.pairs = []nicVipPair{}
}

func VyosHaEntryPoint() {
	server.RegisterAsyncCommandHandler(SET_VYOSHA_PATH, server.VyosLock(setVyosHaHandler))
	if utils.IsHaEabled() {
		go getKeepAlivedStatusTask()
		go keepAlivedCheckTask()
	}
}
