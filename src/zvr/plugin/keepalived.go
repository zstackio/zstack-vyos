package plugin

import (
	"zvr/utils"
	"io/ioutil"
	"fmt"
	"bytes"
	"html/template"
	"os"
	"strings"
	//log "github.com/Sirupsen/logrus"
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
	Nics           []nicVipPair
}

const tKeepalivedNotifyMaster = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
{{ range .VyosHaVipPairs }}
sudo ip add add {{.Vip}}/{{.Prefix}} dev {{.NicName}} || true
{{ end }}
{{ range .Nics }}
sudo ip link set up dev {{.NicName}} || true
{{ end }}
{{ range .VyosHaVipPairs }}
sudo arping -q -A -w 1 -c 2 -I {{.NicName}} {{.Vip}} || true
{{ end }}
{{ range .Nics }}
sudo arping -q -A -w 1 -c 2 -I {{.NicName}} {{.Vip}} || true
{{ end }}

#restart ipsec process
sudo /opt/vyatta/bin/sudo-users/vyatta-vpn-op.pl -op clear-vpn-ipsec-process
`

const tKeepalivedNotifyBackup = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
{{ range .VyosHaVipPairs }}
sudo ip add del {{.Vip}}/{{.Prefix}} dev {{.NicName}} || true
{{ end }}
{{ range .Nics }}
sudo ip link set down dev {{.NicName}} || true
{{ end }}
`

func NewKeepalivedNotifyConf(vyosHaVips []nicVipPair) *KeepalivedNotify {
	notifyNics := []nicVipPair{}
	nics, _ := utils.GetAllNics()
	for _, nic := range nics {
		if nic.Name == "eth0" {
			continue
		}

		if strings.Contains(nic.Name, "eth") {
			bash := utils.Bash{
				Command: fmt.Sprintf("sudo ip -4 -o a show dev %s primary | awk {'print $4'} | head -1 | cut -f1 -d '/'", nic.Name),
			}
			ret, o, _, err := bash.RunWithReturn()
			if err != nil || ret != 0 {
				continue
			}

			o = strings.Trim(o, "\n")
			p := nicVipPair{NicName: nic.Name, Vip: o}
			notifyNics = append(notifyNics, p)
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
	/* # ./keepalived -h
	    Usage: ./keepalived [OPTION...]
            -f, --use-file=FILE          Use the specified configuration file
            -D, --log-detail             Detailed log messages
            -S, --log-facility=[0-7]     Set syslog facility to LOG_LOCAL[0-7]
        */
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo pkill -9 keepalived || sudo %s -D -S 2 -f %s", KeepalivedBinaryFile, KeepalivedConfigFile),
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

/* true master, false backup */
func getKeepAlivedStatus() bool {
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo kill -USR1 $(cat /var/run/keepalived.pid) && cp /tmp/keepalived.data %s && grep 'State' %s  | awk -F '=' '{print $2}'",
			KeepalivedStateFile, KeepalivedStateFile),
		NoLog: true,
	}

	ret, o, _, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return false
	}

	if strings.Contains(o, "MASTER") {
		return true
	} else {
		return false
	}
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
