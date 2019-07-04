package plugin

import (
	"zvr/utils"
	"io/ioutil"
	"fmt"
	"bytes"
	"html/template"
	"os"
	"strings"
)

const (
	KeepalivedRootPath = "/home/vyos/zvr/keepalived/"
	KeepalivedConfigPath = "/home/vyos/zvr/keepalived/conf/"
	KeepalivedSciptPath = "/home/vyos/zvr/keepalived/script/"
	KeepalivedConfigFile = "/home/vyos/zvr/keepalived/conf/keepalived.conf"
	KeepalivedBinaryFile = "/usr/sbin/keepalived"
	KeepalivedBinaryName = "keepalived"
	KeepalivedSciptNotifyMaster = "/home/vyos/zvr/keepalived/script/notifyMaster"
	KeepalivedSciptNotifyBackup = "/home/vyos/zvr/keepalived/script/notifyBackup"
	KeepalivedStateFile = "/home/vyos/zvr/keepalived/conf/state"
	HaproxyHaScriptFile = "/home/vyos/zvr/keepalived/script/haproxy.sh"
)

type KeepalivedNotify struct {
	VyosHaVipPairs []nicVipPair
	Vip            []string
	KeepalivedStateFile string
	HaproxyHaScriptFile string
	Nics           []string
}

const tKeepalivedNotifyMaster = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
echo $1 > {{.KeepalivedStateFile}}
{{ range .VyosHaVipPairs }}
sudo ip add add {{.Vip}}/{{.Prefix}} dev {{.NicName}} || true
{{ end }}
{{ range .VyosHaVipPairs }}
arping -q -A -w 1 -c 2 -I {{.NicName}} {{.Vip}} || true
{{ end }}
{{ range $index, $nic := .Nics }}
ip link set up dev {{$nic}} || true
{{ end }}
`

const tKeepalivedNotifyBackup = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
echo $1 > {{.KeepalivedStateFile}}
{{ range .VyosHaVipPairs }}
sudo ip add del {{.Vip}}/{{.Prefix}} dev {{.NicName}} || true
{{ end }}
{{ range $index, $nic := .Nics }}
ip link set down dev {{$nic}} || true
{{ end }}

`

func NewKeepalivedNotifyConf(vyosHaVips []nicVipPair) *KeepalivedNotify {
	notifyNics := []string{}
	nics, _ := utils.GetAllNics()
	for _, nic := range nics {
		if nic.Name == "eth0" {
			continue
		}

		if strings.Contains(nic.Name, "eth") {
			notifyNics = append(notifyNics, nic.Name)
		}
	}

	knc := &KeepalivedNotify{
		VyosHaVipPairs: vyosHaVips,
		KeepalivedStateFile: KeepalivedStateFile,
		HaproxyHaScriptFile: HaproxyHaScriptFile,
		Nics: notifyNics,
	}

	return knc
}

func (k *KeepalivedNotify) CreateMasterScript () error {
	tmpl, err := template.New("master.conf").Parse(tKeepalivedNotifyMaster); utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k); utils.PanicOnError(err)

	err = ioutil.WriteFile(KeepalivedSciptNotifyMaster, buf.Bytes(), 0755); utils.PanicOnError(err)

	return nil
}

func (k *KeepalivedNotify) CreateBackupScript () error {
	tmpl, err := template.New("backup.conf").Parse(tKeepalivedNotifyBackup); utils.PanicOnError(err)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k); utils.PanicOnError(err)

	err = ioutil.WriteFile(KeepalivedSciptNotifyBackup, buf.Bytes(), 0755); utils.PanicOnError(err)

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
		Interval:  Interval,
		MonitorIps:   MonitorIps,
		LocalIp:   LocalIp,
		PeerIp: PeerIp,
		MasterScript: KeepalivedSciptNotifyMaster,
		BackupScript: KeepalivedSciptNotifyBackup,
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
       script "/bin/ps aux | /bin/grep '/opt/vyatta/sbin/zvr' | /bin/grep -v grep > /dev/null"        # cheaper than pidof
       interval 1                      # check every 2 seconds
       fall 2                          # require 2 failures for KO
       rise 2                          # require 2 successes for OK
}

{{ range .MonitorIps }}
vrrp_script monitor_{{.}} {
	script "/bin/ping {{.}} -w 1 -c 1 > /dev/null"
	interval 1
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
	pid, err := utils.FindFirstPIDByPSExtern(true, KeepalivedBinaryName)
	if err == nil && pid != 0 {
		utils.KillProcess(pid)
	}

	/* # ./keepalived -h
	    Usage: ./keepalived [OPTION...]
            -f, --use-file=FILE          Use the specified configuration file
            -D, --log-detail             Detailed log messages
            -S, --log-facility=[0-7]     Set syslog facility to LOG_LOCAL[0-7]
        */
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo %s -D -S 2 -f %s", KeepalivedBinaryFile, KeepalivedConfigFile),
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

	log_rotatoe_file, err := ioutil.TempFile(KeepalivedConfigPath, "rotation"); utils.PanicOnError(err)
	rotate_conf := `/var/log/keepalived.log {
size 10240k
rotate 20
compress
copytruncate
notifempty
missingok
}`
	_, err = log_rotatoe_file.Write([]byte(rotate_conf)); utils.PanicOnError(err)

	bash := utils.Bash{
		Command: fmt.Sprintf("sudo mv %s /etc/rsyslog.d/keepalived.conf && sudo mv %s /etc/logrotate.d/keepalived && sudo /etc/init.d/rsyslog restart",
			log_file.Name(), log_rotatoe_file.Name()),
	}
	err = bash.Run();utils.PanicOnError(err)
}

func checkKeepalivedRunning()  {
	if pid, _ := utils.FindFirstPIDByPSExtern(true, KeepalivedBinaryName); pid < 0{
		bash := utils.Bash{
			Command: fmt.Sprintf("sudo %s -D -S 2 -f %s", KeepalivedBinaryFile, KeepalivedConfigFile),
		}

		bash.RunWithReturn();
	}

}

func callStatusChangeScripts()  {
	var bash utils.Bash
	if vyosIsMaster {
		bash = utils.Bash{
			Command: fmt.Sprintf("%s MASTER", KeepalivedSciptNotifyMaster),
		}
	} else {
		bash = utils.Bash{
			Command: fmt.Sprintf("%s BACKUP", KeepalivedSciptNotifyBackup),
		}
	}
	bash.RunWithReturn();
}

func init()  {
	os.Mkdir(KeepalivedRootPath, os.ModePerm)
	os.Mkdir(KeepalivedConfigPath, os.ModePerm)
	os.Mkdir(KeepalivedSciptPath, os.ModePerm)
	bash := utils.Bash{
		Command: fmt.Sprintf("echo BACKUP > %s && echo ''> %s && echo ''> %s", KeepalivedStateFile, HaproxyHaScriptFile, KeepalivedConfigFile),
	}
	err := bash.Run();utils.PanicOnError(err)
	enableKeepalivedLog()
}
