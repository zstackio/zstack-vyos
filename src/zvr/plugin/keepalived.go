package plugin

import (
	"zvr/utils"
	"zvr/server"
	"io/ioutil"
	"fmt"
	"bytes"
	"html/template"
	"os"
	"strings"
	"sync/atomic"
	log "github.com/Sirupsen/logrus"
	"os/exec"
)

type KeepAlivedStatus int
const (
	KeepAlivedStatus_Unknown KeepAlivedStatus = iota
	KeepAlivedStatus_Master
	KeepAlivedStatus_Backup
)

const PID_ERROR  = "-1"

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
	KeepalivedPidFile            = "/var/run/keepalived.pid"
	KeepalivedBinaryFile         = "/usr/sbin/keepalived"
	KeepalivedScriptMasterDoGARP = "/home/vyos/zvr/keepalived/script/garp.sh"
	KeepalivedScriptNotifyMaster = "/home/vyos/zvr/keepalived/script/notifyMaster"
	KeepalivedScriptNotifyBackup = "/home/vyos/zvr/keepalived/script/notifyBackup"
)

type KeepalivedNotify struct {
	VyosHaVipPairs []nicVipPair
	MgmtVipPairs []nicVipPair
	Vip            []string
	KeepalivedStateFile string
	HaproxyHaScriptFile string
	NicIps           []nicVipPair
	NicNames          []string
	VrUuid           string
	CallBackUrl      string
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
				Command: fmt.Sprintf("sudo ip -4 -o a show dev %s primary | awk {'print $4'} | head -1 | cut -f1 -d '/'", nic.Name),
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
		MgmtVipPairs: mgmtVips,
		NicNames: nicNames,
		NicIps: nicIps,
		VrUuid: utils.GetVirtualRouterUuid(),
		CallBackUrl: haStatusCallbackUrl,
	}

	return knc
}

func (k* KeepalivedNotify) generateGarpScript () error {
	tmpl, err := template.New("garp.sh").Parse(tSendGratiousARP); utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k); utils.PanicOnError(err)

	return ioutil.WriteFile(KeepalivedScriptMasterDoGARP, buf.Bytes(), 0755)
}

func (k *KeepalivedNotify) CreateMasterScript () error {
	tmpl, err := template.New("master.conf").Parse(tKeepalivedNotifyMaster); utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k); utils.PanicOnError(err)

	err = ioutil.WriteFile(KeepalivedScriptNotifyMaster, buf.Bytes(), 0755); utils.PanicOnError(err)

	err = k.generateGarpScript(); utils.PanicOnError(err)

	/* add log */
	bash := utils.Bash{
		Command: fmt.Sprintf("cat %s", KeepalivedScriptNotifyMaster),
	}
	bash.Run()

	return nil
}

func (k *KeepalivedNotify) CreateBackupScript () error {
	tmpl, err := template.New("backup.conf").Parse(tKeepalivedNotifyBackup); utils.PanicOnError(err)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k); utils.PanicOnError(err)

	err = ioutil.WriteFile(KeepalivedScriptNotifyBackup, buf.Bytes(), 0755); utils.PanicOnError(err)

	/* add log */
	bash := utils.Bash{
		Command: fmt.Sprintf("cat %s", KeepalivedScriptNotifyBackup),
	}
	bash.Run()

	return nil
}

type KeepalivedConf struct {
	HeartBeatNic string
	Interval     int
	MonitorIps []string
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

func (k *KeepalivedConf) BuildConf() (error) {
	tmpl, err := template.New("keepalived.conf").Parse(tKeepalivedConf); utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k); utils.PanicOnError(err)

	err = ioutil.WriteFile(KeepalivedConfigFile, buf.Bytes(), 0644); utils.PanicOnError(err)

	return nil
}

func (k *KeepalivedConf) RestartKeepalived() (error) {
	/* # ./keepalived -h
	    Usage: ./keepalived [OPTION...]
            -f, --use-file=FILE          Use the specified configuration file
            -D, --log-detail             Detailed log messages
            -S, --log-facility=[0-7]     Set syslog facility to LOG_LOCAL[0-7]
        */
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo pkill -9 keepalived; sudo %s -D -S 2 -f %s", KeepalivedBinaryFile, KeepalivedConfigFile),
	}

	bash.RunWithReturn(); bash.PanicIfError()

	return nil
}

func enableKeepalivedLog() {
	log_file, err := ioutil.TempFile(KeepalivedConfigPath, "rsyslog"); utils.PanicOnError(err)
	conf := `$ModLoad imudp
$UDPServerRun 514
local2.debug     /var/log/keepalived.log`
	_, err = log_file.Write([]byte(conf)); utils.PanicOnError(err)

	log_rotate_file, err := ioutil.TempFile(KeepalivedConfigPath, "rotation"); utils.PanicOnError(err)
	rotate_conf := `/var/log/keepalived.log {
size 10240k
rotate 20
compress
copytruncate
notifempty
missingok
}`
	_, err = log_rotate_file.Write([]byte(rotate_conf)); utils.PanicOnError(err)
	utils.SudoMoveFile(log_file.Name(), "/etc/rsyslog.d/keepalived.conf")
	utils.SudoMoveFile(log_rotate_file.Name(), "/etc/logrotate.d/keepalived")
}

func checkKeepalivedRunning()  {
	pid := getKeepalivedPid()
	if pid == PID_ERROR {
		bash := utils.Bash{
			Command: fmt.Sprintf("sudo pkill -9 keepalived; sudo %s -D -S 2 -f %s", KeepalivedBinaryFile, KeepalivedConfigFile),
		}

		bash.RunWithReturn()
	}

}

func callStatusChangeScripts()  {
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
	bash.RunWithReturn();
}

func getKeepalivedPid() (string) {
	stdout, err := exec.Command("pidof", "-x", KeepalivedBinaryFile).Output()
	if err != nil {
		log.Debugf("get keepalived pid failed %v", err)
		return PID_ERROR
	}

	/* when keepalived is running, the output will be: 3657, 3656, 3655
	   when keepalived not runing, the output will be empty */
	out := strings.TrimSpace(string(stdout))
	if out == "" {
		log.Debugf("keepalived is not running")
		return PID_ERROR
	}

	pids := strings.Fields(out)
	return pids[len(pids)-1]
}

/* true master, false backup */
func getKeepAlivedStatus() KeepAlivedStatus {
	pid := getKeepalivedPid()
	if pid == PID_ERROR {
		return KeepAlivedStatus_Unknown
	}

	bash := utils.Bash{
		Command: fmt.Sprintf("timeout 1 sudo kill -USR1 %s; grep 'State' /tmp/keepalived.data  | awk -F '=' '{print $2}'",
			pid),
		NoLog: true,
	}

	ret, o, e, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		log.Debugf("get keepalived status %s", e)
		return KeepAlivedStatus_Unknown
	}

	if strings.Contains(o, "MASTER") {
		return KeepAlivedStatus_Master
	} else if strings.Contains(o, "BACKUP"){
		return KeepAlivedStatus_Backup
	} else if strings.Contains(o, "FAULT"){
		return KeepAlivedStatus_Backup
	} else {
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

func KeepalivedEntryPoint() {
	server.RegisterSyncCommandHandler(KEEPALIVED_GARP_PATH, garpHandler)
}

var keepAlivedStatus KeepAlivedStatus

func init()  {
	os.Mkdir(KeepalivedRootPath, os.ModePerm)
	os.Mkdir(KeepalivedConfigPath, os.ModePerm)
	os.Mkdir(KeepalivedSciptPath, os.ModePerm)
	os.Remove(KeepalivedScriptNotifyMaster)
	os.Remove(KeepalivedScriptNotifyBackup)

	enableKeepalivedLog()
}
