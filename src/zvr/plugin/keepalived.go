package plugin

import (
	"bytes"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"html/template"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
	"zvr/server"
	"zvr/utils"
)

type KeepAlivedStatus int

const (
	KeepAlivedStatus_Unknown KeepAlivedStatus = iota
	KeepAlivedStatus_Master
	KeepAlivedStatus_Backup
)

const PID_ERROR = -1

const (
	KEEPALIVED_GARP_PATH = "/keepalived/garp"
)

func (s KeepAlivedStatus) string() string {
	switch s {
	case KeepAlivedStatus_Unknown:
		return "Unknown"
	case KeepAlivedStatus_Master:
		return "Master"
	case KeepAlivedStatus_Backup:
		return "Backup"
	default:
		log.Debugf("!!! get a unexpected keepalived status")
		return "DEFAULT"
	}
}

const (
	KeepalivedRootPath           = "/home/vyos/zvr/keepalived/"
	KeepalivedConfigPath         = "/home/vyos/zvr/keepalived/conf/"
	KeepalivedSciptPath          = "/home/vyos/zvr/keepalived/script/"
	KeepalivedConfigFile         = "/home/vyos/zvr/keepalived/conf/keepalived.conf"
	ConntrackdConfigFile         = "/home/vyos/zvr/keepalived/conf/conntrackd.conf"
	ConntrackdBinaryFile         = "/usr/sbin/conntrackd"
	KeepalivedPidFile            = "/var/run/keepalived.pid"
	KeepalivedBinaryFile         = "/usr/sbin/keepalived"
	KeepalivedScriptMasterDoGARP = "/home/vyos/zvr/keepalived/script/garp.sh"
	KeepalivedScriptNotifyMaster = "/home/vyos/zvr/keepalived/script/notifyMaster"
	KeepalivedScriptNotifyBackup = "/home/vyos/zvr/keepalived/script/notifyBackup"
	ConntrackScriptPrimaryBackup = "/home/vyos/zvr/keepalived/script/primary-backup.sh"
)

type KeepalivedNotify struct {
	VyosHaVipPairs      []nicVipPair
	MgmtVipPairs        []nicVipPair
	Vip                 []string
	KeepalivedStateFile string
	HaproxyHaScriptFile string
	NicIps              []nicVipPair
	NicNames            []string
	VrUuid              string
	CallBackUrl         string
}

const tSendGratiousARP = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
logger "Sending gratious ARP" || true

{{ range .VyosHaVipPairs }}
(sudo arping -q -A -c 3 -I {{.NicName}} {{.Vip}}) &
{{ end }}
{{ range .NicIps }}
(sudo arping -q -A -c 3 -I {{.NicName}} {{.Vip}}) &
{{ end }}
`

const tKeepalivedNotifyMaster = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
{{ range .MgmtVipPairs }}
sudo ip add add {{.Vip}}/{{.Prefix}} dev {{.NicName}} || true
{{ end }}

{{ range $index, $name := .NicNames }}
sudo ip link set up dev {{$name}} || true
{{ end }}

#send Gratuitous ARP
(/bin/bash /home/vyos/zvr/keepalived/script/garp.sh) &

#restart ipsec process
(/bin/bash /home/vyos/zvr/keepalived/script/ipsec.sh) &

#restart flow-accounting process
(/bin/bash /home/vyos/zvr/keepalived/script/flow.sh) &

#reload pimd config
(/bin/bash /home/vyos/zvr/keepalived/script/pimd.sh) &

#add policy route
(/bin/bash /home/vyos/zvr/keepalived/script/policyRoutes.sh) &

#start dhcp server
(/bin/bash /home/vyos/zvr/keepalived/script/dhcpd.sh) &

#add default route
(/bin/bash /home/vyos/zvr/keepalived/script/defaultroute.sh) &

#sync conntrackd
#(/bin/bash /home/vyos/zvr/keepalived/script/primary-backup.sh primary) &

#notify Mn node
(curl -H "Content-Type: application/json" -H "commandpath: /vpc/hastatus" -X POST -d '{"virtualRouterUuid": "{{.VrUuid}}", "haStatus":"Master"}' {{.CallBackUrl}}) &

#this is for debug
ip add
`

const tKeepalivedNotifyBackup = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
port=7272
peerIp=$(echo $(grep -A1 -w unicast_peer /home/vyos/zvr/keepalived/conf/keepalived.conf | tail -1))
test x"$2" != x"" && port=$2
test x"$peerIp" != x"" && curl -X POST -H "User-Agent: curl/7.2.5" --connect-timeout 3 http://"$peerIp:$port"/keepalived/garp

#/bin/bash /home/vyos/zvr/keepalived/script/primary-backup.sh "$1"

{{ range .MgmtVipPairs }}
sudo ip add del {{.Vip}}/{{.Prefix}} dev {{.NicName}} || true
{{ end }}

{{ range $index, $name := .NicNames }}
sudo ip link set down dev {{$name}} || true
{{ end }}
#notify Mn node
(curl -H "Content-Type: application/json" -H "commandpath: /vpc/hastatus" -X POST -d '{"virtualRouterUuid": "{{.VrUuid}}", "haStatus":"Backup"}' {{.CallBackUrl}}) &
#this is for debug
ip add
`

func NewKeepalivedNotifyConf(vyosHaVips, mgmtVips []nicVipPair) *KeepalivedNotify {
	nicIps := []nicVipPair{}
	nicNames := []string{}
	nics, _ := utils.GetAllNics()
	for _, nic := range nics {
		if nic.Name == "eth0" {
			continue
		}

		if strings.Contains(nic.Name, "eth") {
			nicNames = append(nicNames, nic.Name)

			bash := utils.Bash{
				Command: fmt.Sprintf("sudo ip -4 -o a show dev %s primary | awk '{print $4; exit}' | cut -f1 -d '/'", nic.Name),
			}
			ret, o, _, err := bash.RunWithReturn()
			if err != nil || ret != 0 {
				continue
			}

			o = strings.Trim(o, " \t\n")
			if o == "" {
				continue
			}

			p := nicVipPair{NicName: nic.Name, Vip: o}
			nicIps = append(nicIps, p)
		}
	}

	knc := &KeepalivedNotify{
		VyosHaVipPairs: vyosHaVips,
		MgmtVipPairs:   mgmtVips,
		NicNames:       nicNames,
		NicIps:         nicIps,
		VrUuid:         utils.GetVirtualRouterUuid(),
		CallBackUrl:    haStatusCallbackUrl,
	}

	return knc
}

func (k *KeepalivedNotify) generateGarpScript() error {
	tmpl, err := template.New("garp.sh").Parse(tSendGratiousARP)
	utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	return ioutil.WriteFile(KeepalivedScriptMasterDoGARP, buf.Bytes(), 0755)
}

func (k *KeepalivedNotify) CreateMasterScript() error {
	tmpl, err := template.New("master.conf").Parse(tKeepalivedNotifyMaster)
	utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	err = ioutil.WriteFile(KeepalivedScriptNotifyMaster, buf.Bytes(), 0755)
	utils.PanicOnError(err)

	err = k.generateGarpScript()
	utils.PanicOnError(err)

	log.Debugf("%s: %s", KeepalivedScriptNotifyMaster, buf.String())

	return nil
}

func (k *KeepalivedNotify) CreateBackupScript() error {
	err := ioutil.WriteFile(ConntrackScriptPrimaryBackup, []byte(primaryBackupScript), 0750)
	utils.PanicOnError(err)

	tmpl, err := template.New("backup.conf").Parse(tKeepalivedNotifyBackup)
	utils.PanicOnError(err)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	err = ioutil.WriteFile(KeepalivedScriptNotifyBackup, buf.Bytes(), 0755)
	utils.PanicOnError(err)

	log.Debugf("%s: %s", KeepalivedScriptNotifyBackup, buf.String())

	return nil
}

type KeepalivedConf struct {
	HeartBeatNic string
	Interval     int
	MonitorIps   []string
	LocalIp      string
	PeerIp       string

	MasterScript string
	BackupScript string
}

func NewKeepalivedConf(hearbeatNic, LocalIp, PeerIp string, MonitorIps []string, Interval int) *KeepalivedConf {
	kc := &KeepalivedConf{
		HeartBeatNic: hearbeatNic,
		Interval:     Interval,
		MonitorIps:   MonitorIps,
		LocalIp:      LocalIp,
		PeerIp:       PeerIp,
		MasterScript: KeepalivedScriptNotifyMaster,
		BackupScript: KeepalivedScriptNotifyBackup,
	}

	return kc
}

const tConntrackdConf = `# This file is auto-generated, edit with caution!
Sync {
    Mode FTFW {
        DisableExternalCache Off
        CommitTimeout 1800
        PurgeTimeout 5
    }

    UDP {
        IPv4_address {{.LocalIp}}
        IPv4_Destination_Address {{.PeerIp}}
        Port 3780
        Interface {{.HeartBeatNic}}
        SndSocketBuffer 1249280
        RcvSocketBuffer 1249280
        Checksum on
    }
}

General {
    Nice -20
    HashSize 1421312
    HashLimit 45481984  # 2 * nf_conntrack_max
    LogFile off
    Syslog off
    LockFile /var/lock/conntrack.lock
    UNIX {
        Path /var/run/conntrackd.ctl
        Backlog 20
    }
    NetlinkBufferSize 2097152
    NetlinkBufferSizeMaxGrowth 8388608
    Filter From Userspace {
        Protocol Accept {
            TCP
            SCTP
            DCCP
            # UDP
            # ICMP # This requires a Linux kernel >= 2.6.31
        }
        Address Ignore {
            IPv4_address 127.0.0.1 # loopback
            IPv4_address {{.LocalIp}}
            IPv4_address {{.PeerIp}}
        }
    }
}
`

const tKeepalivedConf = `# This file is auto-generated, edit with caution!
global_defs {
	vrrp_garp_master_refresh 60
	vrrp_check_unicast_src
	script_user root
}

vrrp_script monitor_zvr {
       script "/usr/bin/pgrep -u vyos -f /opt/vyatta/sbin/zvr > /dev/null"        # cheaper than pidof
       interval 2                      # check every 2 seconds
       fall 2                          # require 2 failures for KO
       rise 2                          # require 2 successes for OK
}

{{ range .MonitorIps }}
vrrp_script monitor_{{.}} {
	script "/bin/ping {{.}} -w 1 -c 1 > /dev/null"
	interval 2
	weight -2
	fall 3
	rise 3
}
{{ end }}

vrrp_instance vyos-ha {
	state BACKUP
	interface {{.HeartBeatNic}}
	virtual_router_id 50
	priority 100
	advert_int {{.Interval}}
	nopreempt

	unicast_src_ip {{.LocalIp}}
	unicast_peer {
		{{.PeerIp}}
	}

	track_script {
		monitor_zvr
{{ range .MonitorIps }}
                monitor_{{.}}
{{ end }}
	}

	notify_master "{{.MasterScript}} MASTER"
	notify_backup "{{.BackupScript}} BACKUP"
	notify_fault "{{.BackupScript}} FAULT"
}
`

func (k *KeepalivedConf) BuildConf() error {
	tmpl, err := template.New("keepalived.conf").Parse(tKeepalivedConf)
	utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	err = ioutil.WriteFile(KeepalivedConfigFile, buf.Bytes(), 0644)
	utils.PanicOnError(err)

	// generate conntrackd.conf
	buf.Reset()
	tmpl, err = template.New("conntrackd.conf").Parse(tConntrackdConf)
	utils.PanicOnError(err)
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)
	return ioutil.WriteFile(ConntrackdConfigFile, buf.Bytes(), 0644)
}

func doRestartKeepalived(reloadExisting bool) error {
	/* # ./keepalived -h
		    Usage: ./keepalived [OPTION...]
	            -f, --use-file=FILE          Use the specified configuration file
	            -D, --log-detail             Detailed log messages
	            -S, --log-facility=[0-7]     Set syslog facility to LOG_LOCAL[0-7]
	*/
	pid := getKeepalivedPid()
	if pid == PID_ERROR {
		bash := utils.Bash{
			Command: fmt.Sprintf("sudo pkill -9 keepalived; sudo %s -D -S 2 -f %s -p %s", KeepalivedBinaryFile, KeepalivedConfigFile, KeepalivedPidFile),
		}
		return bash.Run()
	}

	if reloadExisting {
		bash := utils.Bash{
			Command: fmt.Sprintf("sudo kill -HUP %d", pid),
		}
		return bash.Run()
	}

	bash := utils.Bash{
		Command: fmt.Sprintf("kill -TERM %d; %s -D -S 2 -f %s -p %s", pid, KeepalivedBinaryFile, KeepalivedConfigFile, KeepalivedPidFile),
		Sudo:    true,
	}
	return bash.Run()
}

func (k *KeepalivedConf) RestartKeepalived() {
	err := doRestartKeepalived(true)
	utils.PanicOnError(err)
}

func enableKeepalivedLog() {
	log_file, err := ioutil.TempFile(KeepalivedConfigPath, "rsyslog")
	utils.PanicOnError(err)
	conf := `$ModLoad imudp
$UDPServerRun 514
local2.debug     /var/log/keepalived.log`
	_, err = log_file.Write([]byte(conf))
	utils.PanicOnError(err)

	log_rotate_file, err := ioutil.TempFile(KeepalivedConfigPath, "rotation")
	utils.PanicOnError(err)
	rotate_conf := `/var/log/keepalived.log {
size 10240k
rotate 20
compress
copytruncate
notifempty
missingok
}`
	_, err = log_rotate_file.Write([]byte(rotate_conf))
	utils.PanicOnError(err)
	utils.SudoMoveFile(log_file.Name(), "/etc/rsyslog.d/keepalived.conf")
	utils.SudoMoveFile(log_rotate_file.Name(), "/etc/logrotate.d/keepalived")
}

func checkConntrackdRunning() {
	if getConntrackdPid() != PID_ERROR {
		return
	}

	bash := utils.Bash{
		Command: fmt.Sprintf("sudo %s -C %s -d", ConntrackdBinaryFile, ConntrackdConfigFile),
	}

	bash.RunWithReturn()
}

func checkKeepalivedRunning() {
	pid := getKeepalivedPid()
	if pid == PID_ERROR {
		bash := utils.Bash{
			Command: fmt.Sprintf("sudo pkill -9 keepalived; sudo %s -D -S 2 -f %s -p %s", KeepalivedBinaryFile, KeepalivedConfigFile, KeepalivedPidFile),
		}

		bash.RunWithReturn()
	}

}

func callStatusChangeScripts() {
	var bash utils.Bash
	log.Debugf("!!! KeepAlived status change to %s", keepAlivedStatus.string())
	if keepAlivedStatus == KeepAlivedStatus_Master {
		bash = utils.Bash{
			Command: fmt.Sprintf("cat %s; %s MASTER", KeepalivedScriptNotifyMaster, KeepalivedScriptNotifyMaster),
		}
	} else if keepAlivedStatus == KeepAlivedStatus_Backup {
		bash = utils.Bash{
			Command: fmt.Sprintf("cat %s; %s BACKUP %d", KeepalivedScriptNotifyBackup, KeepalivedScriptNotifyBackup, server.CommandOptions.Port),
		}
	}
	bash.RunWithReturn()
}

var keepalivedPID int

func getKeepalivedPid() int {
	if keepalivedPID > 0 && utils.ProcessExists(keepalivedPID) == nil {
		return keepalivedPID
	}

	if pid, err := utils.FindFirstPID(KeepalivedBinaryFile); err != nil {
		log.Debugf("%s", err)
		return PID_ERROR
	} else {
		keepalivedPID = pid
		return pid
	}
}

var conntrackdPID int

func getConntrackdPid() int {
	if conntrackdPID > 0 && utils.ProcessExists(conntrackdPID) == nil {
		return conntrackdPID
	}

	if pid, err := utils.FindFirstPID(ConntrackdBinaryFile); err != nil {
		log.Debugf("%s", err)
		return PID_ERROR
	} else {
		conntrackdPID = pid
		return pid
	}
}

/* true master, false backup */
func getKeepAlivedStatus() KeepAlivedStatus {
	pid := getKeepalivedPid()
	if pid == PID_ERROR {
		return KeepAlivedStatus_Unknown
	}

	bash := utils.Bash{
		// There is race between generating keepalived.data and reading its content.
		Command: fmt.Sprintf("timeout 1 sudo kill -USR1 %d; sleep 0.1; awk -F '=' '/State/{print $2}' /tmp/keepalived.data",
			pid),
		NoLog: true,
	}

	ret, o, e, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		log.Debugf("get keepalived status %s", e)
		return KeepAlivedStatus_Unknown
	}

	switch strings.TrimSpace(o) {
	case "MASTER":
		return KeepAlivedStatus_Master
	case "BACKUP":
		return KeepAlivedStatus_Backup
	case "FAULT":
		return KeepAlivedStatus_Backup
	default:
		return KeepAlivedStatus_Unknown
	}
}

var garp_counter uint32

func garpHandler(ctx *server.CommandContext) interface{} {
	if atomic.AddUint32(&garp_counter, 1) > 1 {
		return nil // garp in progress
	}

	go func() {
		err := exec.Command("sudo", "/bin/sh", KeepalivedScriptMasterDoGARP).Run()
		log.Debugf("master garp: %s", err)
		atomic.StoreUint32(&garp_counter, 0)
	}()

	return nil
}

const _zvr_shm = "/dev/shm/zvr.log"

func KeepalivedEntryPoint() {
	utils.RegisterDiskFullHandler(func(e error) {
		if IsMaster() {
			s := time.Now().Format(time.RFC3339) + " " + e.Error() + "\n"
			ioutil.WriteFile(_zvr_shm, []byte(s), 0640)
			doRestartKeepalived(false)
		}
	})

	server.RegisterSyncCommandHandler(KEEPALIVED_GARP_PATH, garpHandler)
}

var keepAlivedStatus KeepAlivedStatus

func init() {
	os.Remove(_zvr_shm)
	os.Mkdir(KeepalivedRootPath, os.ModePerm)
	os.Mkdir(KeepalivedConfigPath, os.ModePerm)
	os.Mkdir(KeepalivedSciptPath, os.ModePerm)
	os.Remove(KeepalivedScriptNotifyMaster)
	os.Remove(KeepalivedScriptNotifyBackup)

	enableKeepalivedLog()
}
