package plugin

import (
	"zvr/server"
	"fmt"
	"zvr/utils"
	//log "github.com/Sirupsen/logrus"
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
}

type macVipPair struct {
	NicMac string     	`json:"nicMac"`
	NicVip     string  	`json:"nicVip"`
	Netmask     string  	`json:"netmask"`
	Category     string  	`json:"category"`
}

var vyosHaEnabled bool
var vyosIsMaster bool

func setVyosHaHandler(ctx *server.CommandContext) interface{} {
	cmd := &setVyosHaCmd{}
	ctx.GetCommand(cmd)

	heartbeatNicNme, _ := utils.GetNicNameByMac(cmd.HeartbeatNic)
	/* add firewall */
	tree := server.NewParserFromShowConfiguration().Tree
	if utils.IsSkipVyosIptables() {
		/* TODO */
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
	}

	pairs := []nicVipPair{}
	for _, p := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(p.NicMac); utils.PanicOnError(err)
		cidr, err := utils.NetmaskToCIDR(p.Netmask); utils.PanicOnError(err)
		pairs = append(pairs, nicVipPair{NicName: nicname, Vip: p.NicVip, Prefix:cidr})

		addSecondaryIpFirewall(nicname, p.NicVip, tree)

		tree.AttachFirewallToInterface(nicname, "local")
	}

	tree.Apply(false)

	/* generate notify script first */
	addHaNicVipPair(pairs)

	if cmd.PeerIp == "" {
		cmd.PeerIp = cmd.LocalIp
	}
	keepalivedConf := NewKeepalivedConf(heartbeatNicNme, cmd.LocalIp, cmd.PeerIp, cmd.Monitors, cmd.Keepalive)
	keepalivedConf.BuildConf()
	keepalivedConf.RestartKeepalived()

	vyosHaEnabled = true

	go vyosHaStatusCheckTask()
	go keepAlivedCheckTask()

	return nil
}

func IsVyosHaEnabled() bool {
	return vyosHaEnabled
}

func IsMaster() bool {
	return vyosIsMaster
}

func getHaStatus() bool {
	bash := utils.Bash{
		Command: fmt.Sprintf("cat %s", KeepalivedStateFile),
		NoLog: true,
	}

	ret, o, _, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return vyosIsMaster
	}

	if strings.Contains(o, "MASTER") {
		return true
	} else {
		return false
	}
}

func vyosHaStatusCheckTask()  {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for  {
		select {
		case <-ticker.C:
			newHaStatus := getHaStatus()
			if newHaStatus == vyosIsMaster {
				continue
			}

		        /* there is a situation when zvr write the keepalived notify script,
		           at the same time keepalived is changing state,
		           so when zvr detect status change, all script again to make sure no missing config */
			vyosIsMaster = newHaStatus
			server.VyosLockInterface(callStatusChangeScripts)()
		}
	}
}

func keepAlivedCheckTask()  {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for  {
		select {
		case <-ticker.C:
			checkKeepalivedRunning()
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

func generateNotigyScripts(vyosHaVips []nicVipPair)  {
	keepalivedNofityConf := NewKeepalivedNotifyConf(vyosHaVips)
	keepalivedNofityConf.CreateMasterScript()
	keepalivedNofityConf.CreateBackupScript()
}

func addHaNicVipPair(pairs []nicVipPair)  {
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

	generateNotigyScripts(haVipPairs.pairs)
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
		generateNotigyScripts(haVipPairs.pairs)
	}
}

var haVipPairs  vyosNicVipPairs
func init() {
	vyosHaEnabled = false
	vyosIsMaster = false
	haVipPairs.pairs = []nicVipPair{}
}

func VyosHaEntryPoint() {
	server.RegisterAsyncCommandHandler(SET_VYOSHA_PATH, server.VyosLock(setVyosHaHandler))
}
