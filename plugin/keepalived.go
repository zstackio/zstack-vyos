package plugin

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	"io/fs"

	log "github.com/sirupsen/logrus"
)

type KeepAlivedStatus int

const (
	KeepAlivedStatus_Unknown KeepAlivedStatus = iota
	KeepAlivedStatus_Master
	KeepAlivedStatus_Backup
)

type KeepAlivedProcessAction int

const (
	KeepAlivedProcess_Reload KeepAlivedProcessAction = iota
	KeepAlivedProcess_Restart
	KeepAlivedProcess_Start
	KeepAlivedProcess_Skip
)

const PID_ERROR = -1

const (
	KEEPALIVED_GARP_PATH = "/keepalived/garp"
	KEEPALIVED_STATE_PATH = "/tmp/keepalived_state"
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
	ConntrackdBinaryFile = "/usr/sbin/conntrackd"
	KeepalivedPidFile    = "/var/run/keepalived.pid"
	KeepalivedBinaryFile = "/usr/sbin/keepalived"
)

func getKeepalivedRootPath() string {
	return filepath.Join(utils.GetZvrRootPath(), "keepalived/")
}

func getKeepalivedConfigPath() string {
	return filepath.Join(getKeepalivedRootPath(), "conf/")
}

func getKeepalivedScriptPath() string {
	return filepath.Join(getKeepalivedRootPath(), "script/");
}       

func getKeepalivedConfigFile() string {
	return filepath.Join(getKeepalivedRootPath(), "conf/keepalived.conf")
}

func	getConntrackdConfigFile() string {
	return filepath.Join(getKeepalivedRootPath(), "conf/conntrackd.conf")
}           

func getKeepalivedScriptMasterDoGARP() string {
	return filepath.Join(getKeepalivedRootPath(), "script/garp.sh")
}    

func getKeepalivedScriptMasterDoIpv6Dad() string {
	return filepath.Join(getKeepalivedRootPath(), "script/ipv6Dad.sh")
} 

func getKeepalivedScriptNotifyMaster() string {
	return filepath.Join(getKeepalivedRootPath(), "script/notifyMaster")
}    

func getKeepalivedScriptNotifyBackup()  string {
	return filepath.Join(getKeepalivedRootPath(), "script/notifyBackup")
} 
	
func getConntrackScriptPrimaryBackup() string {
	return filepath.Join(getKeepalivedRootPath(), "script/primary-backup.sh")
}   

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
	DoGARPScript        string
	DoIpv6DadScript     string
	IpsecScript         string
	FlowScript          string
	PimdScript          string
	DhcpdScript         string
	DnsmasqScript       string
	KeepalivedCfg       string
	DefaultRouteScript  string
	PrimaryBackupScript string
}

const tSendGratiousARP = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
logger "Sending gratious ARP" || true

{{ range .VyosHaVipPairs }}
{{ if .Vip }}
(sudo arping -q -A -c 3 -I {{.NicName}} {{.Vip}}) &
{{ else if .Vip6 }}
(ndsend {{.Vip6}} {{.NicName}}) &
{{end}}
{{ end }}
{{ range .NicIps }}
(sudo arping -q -A -c 3 -I {{.NicName}} {{.Vip}}) &
{{ end }}
`

const tSetIpv6InterfaceDadSuccess = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
logger "set ipv6 interface dad success" || true
seconds=0

while [ $seconds -lt 60 ]; do
{{- range .VyosHaVipPairs }}
{{- if .Vip6 }}
ipv6=$(ip -6 addr show dev {{.NicName}} | grep {{.Vip6}}|awk '/dad/{print $2}')
if [ x$ipv6 != x"" ]; then
	ip -6 a del $ipv6 dev {{.NicName}} && ip -6 a add $ipv6 dev {{.NicName}}
	ndsend {{.Vip6}} {{.NicName}}
fi
{{- end}}
{{- end}}
sleep 3

seconds=$((seconds + 3))
done
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
(/bin/bash {{.DoGARPScript}}) &

#do ipv6 dad
(/bin/bash {{.DoIpv6DadScript}}) &

#restart ipsec process
(/bin/bash {{.IpsecScript}}) &

#restart flow-accounting process
(/bin/bash {{.FlowScript}}) &

#reload pimd config
(/bin/bash {{.PimdScript}}) &

#start dhcp server
(/bin/bash {{.DhcpdScript}}) &

#start dns server
(/bin/bash {{.DnsmasqScript}}) &

#add default route
(/bin/bash {{.DefaultRouteScript}}) &

#sync conntrackd
#(/bin/bash {{.PrimaryBackupScript}} primary) &

#notify Mn node
(curl -A "zstack zvr" -H "Content-Type: application/json" -H "commandpath: /vpc/hastatus" -X POST -d '{"virtualRouterUuid": "{{.VrUuid}}", "haStatus":"Master"}' {{.CallBackUrl}}) &

#write satet
echo "MASTER" > /tmp/keepalived_state
#this is for debug
ip add
`

const tKeepalivedNotifySlbMaster = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
#notify Mn node
(curl -A "zstack zvr" -H "Content-Type: application/json" -H "commandpath: /vpc/hastatus" -X POST -d '{"virtualRouterUuid": "{{.VrUuid}}", "haStatus":"Master"}' {{.CallBackUrl}}) &

echo "MASTER" > /tmp/keepalived_state
`

const tKeepalivedNotifyBackup = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
port=7272
peerIp=$(echo $(grep -A1 -w unicast_peer {{.KeepalivedCfg}} | tail -1))
test x"$2" != x"" && port=$2
test x"$peerIp" != x"" && curl -X POST -H "User-Agent: curl/7.2.5" --connect-timeout 3 http://"$peerIp:$port"/keepalived/garp

#/bin/bash {{.PrimaryBackupScript}} "$1"

{{ range .MgmtVipPairs }}
sudo ip add del {{.Vip}}/{{.Prefix}} dev {{.NicName}} || true
{{ end }}

{{ range $index, $name := .NicNames }}
sudo ip link set down dev {{$name}} || true
{{ end }}
#notify Mn node
(curl  -A "zstack zvr" -H "Content-Type: application/json" -H "commandpath: /vpc/hastatus" -X POST -d '{"virtualRouterUuid": "{{.VrUuid}}", "haStatus":"Backup"}' {{.CallBackUrl}}) &
echo "BACKUP" > /tmp/keepalived_state
#this is for debug
ip add
`

const tKeepalivedNotifySLbBackup = `#!/bin/sh
# This file is auto-generated, DO NOT EDIT! DO NOT EDIT!! DO NOT EDIT!!!
#notify Mn node
(curl -A "zstack zvr" -H "Content-Type: application/json" -H "commandpath: /vpc/hastatus" -X POST -d '{"virtualRouterUuid": "{{.VrUuid}}", "haStatus":"Backup"}' {{.CallBackUrl}}) &
echo "BACKUP" > /tmp/keepalived_state
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
		VyosHaVipPairs:      vyosHaVips,
		MgmtVipPairs:        mgmtVips,
		NicNames:            nicNames,
		NicIps:              nicIps,
		VrUuid:              utils.GetVirtualRouterUuid(),
		CallBackUrl:         haStatusCallbackUrl,
		IpsecScript:         filepath.Join(getKeepalivedScriptPath(), "ipsec.sh"),
		FlowScript:          filepath.Join(getKeepalivedScriptPath(), "flow.sh"),
		PimdScript:          filepath.Join(getKeepalivedScriptPath(), "pimd.sh"),
		DhcpdScript:         filepath.Join(getKeepalivedScriptPath(), "dhcpd.sh"),
		DnsmasqScript:       filepath.Join(getKeepalivedScriptPath(), "dnsmasq.sh"),
		DoGARPScript:        getKeepalivedScriptMasterDoGARP(),
		DoIpv6DadScript:     getKeepalivedScriptMasterDoIpv6Dad(),
		KeepalivedCfg:       getKeepalivedConfigFile(),
		PrimaryBackupScript: getConntrackScriptPrimaryBackup(),
		DefaultRouteScript:  filepath.Join(getKeepalivedScriptPath(), "defaultroute.sh"),
	}

	return knc
}

func (k *KeepalivedNotify) generateGarpScript() error {
	tmpl, err := template.New("garp.sh").Parse(tSendGratiousARP)
	utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	
	if utils.IsEuler2203() {
		os.WriteFile(getKeepalivedScriptMasterDoGARP(), buf.Bytes(), 0700)
		return utils.SetFileOwner(getKeepalivedScriptMasterDoGARP(), utils.GetZvrUser(), utils.GetZvrUser())
	} else {
		return os.WriteFile(getKeepalivedScriptMasterDoGARP(), buf.Bytes(), 0755)
	}
}

func (k *KeepalivedNotify) generateIpv6DadScript() error {
	tmpl, err := template.New("ipv6Dad.sh").Parse(tSetIpv6InterfaceDadSuccess)
	utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	if utils.IsEuler2203() {
		os.WriteFile(getKeepalivedScriptMasterDoIpv6Dad(), buf.Bytes(), 0700)
		return utils.SetFileOwner(getKeepalivedScriptMasterDoIpv6Dad(), utils.GetZvrUser(), utils.GetZvrUser())
	} else {
		return os.WriteFile(getKeepalivedScriptMasterDoIpv6Dad(), buf.Bytes(), 0755)
	}
}

func (k *KeepalivedNotify) CreateMasterScript() error {
	tmpl, err := template.New("master.conf").Parse(tKeepalivedNotifyMaster)
	utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	if utils.IsEuler2203() {
		err = os.WriteFile(getKeepalivedScriptNotifyMaster(), buf.Bytes(), 0700)
		utils.PanicOnError(err)
		utils.SetFileOwner(getKeepalivedScriptNotifyMaster(), utils.GetZvrUser(), utils.GetZvrUser())
	} else {
		err = os.WriteFile(getKeepalivedScriptNotifyMaster(), buf.Bytes(), 0755)
		utils.PanicOnError(err)
	}

	err = k.generateGarpScript()
	utils.PanicOnError(err)

	err = k.generateIpv6DadScript()
	utils.PanicOnError(err)

	log.Debugf("%s: %s", getKeepalivedScriptNotifyMaster(), buf.String())

	return nil
}

func (k *KeepalivedNotify) CreateBackupScript() error {
	if utils.IsEuler2203() {
		err := os.WriteFile(getConntrackScriptPrimaryBackup(), []byte(primaryBackupScript), 0700)
		utils.PanicOnError(err)
		utils.SetFileOwner(getConntrackScriptPrimaryBackup(), utils.GetZvrUser(), utils.GetZvrUser())
	} else {
		err := os.WriteFile(getConntrackScriptPrimaryBackup(), []byte(primaryBackupScript), 0755)
		utils.PanicOnError(err)
	}

	tmpl, err := template.New("backup.conf").Parse(tKeepalivedNotifyBackup)
	utils.PanicOnError(err)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	if utils.IsEuler2203() {
		err = os.WriteFile(getKeepalivedScriptNotifyBackup(), buf.Bytes(), 0700)
		utils.PanicOnError(err)
		utils.SetFileOwner(getKeepalivedScriptNotifyBackup(), utils.GetZvrUser(), utils.GetZvrUser())
	} else {
		err = os.WriteFile(getKeepalivedScriptNotifyBackup(), buf.Bytes(), 0755)
		utils.PanicOnError(err)
	}
	

	log.Debugf("%s: %s", getKeepalivedScriptNotifyBackup(), buf.String())

	return nil
}

func (k *KeepalivedNotify) CreateSlbMasterScript() error {
	tmpl, err := template.New("master.conf").Parse(tKeepalivedNotifySlbMaster)
	utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	if utils.IsEuler2203() {
		err = os.WriteFile(getKeepalivedScriptNotifyMaster(), buf.Bytes(), 0700)
		utils.PanicOnError(err)
		utils.SetFileOwner(getKeepalivedScriptNotifyMaster(), utils.GetZvrUser(), utils.GetZvrUser())
	} else {
		err = os.WriteFile(getKeepalivedScriptNotifyMaster(), buf.Bytes(), 0755)
		utils.PanicOnError(err)
	}

	log.Debugf("%s: %s", getKeepalivedScriptNotifyMaster(), buf.String())

	return nil
}

func (k *KeepalivedNotify) CreateSlbBackupScript() error {
	if utils.IsEuler2203() {
		err := os.WriteFile(getConntrackScriptPrimaryBackup(), []byte(primaryBackupScript), 0700)
		utils.PanicOnError(err)
		utils.SetFileOwner(getConntrackScriptPrimaryBackup(), utils.GetZvrUser(), utils.GetZvrUser())
	} else {
		err := os.WriteFile(getConntrackScriptPrimaryBackup(), []byte(primaryBackupScript), 0755)
		utils.PanicOnError(err)
	}

	tmpl, err := template.New("backup.conf").Parse(tKeepalivedNotifySLbBackup)
	utils.PanicOnError(err)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	if utils.IsEuler2203() {
		err = os.WriteFile(getKeepalivedScriptNotifyBackup(), buf.Bytes(), 0700)
		utils.PanicOnError(err)
		utils.SetFileOwner(getKeepalivedScriptNotifyBackup(), utils.GetZvrUser(), utils.GetZvrUser())
	} else {
		err = os.WriteFile(getKeepalivedScriptNotifyBackup(), buf.Bytes(), 0755)
		utils.PanicOnError(err)
	}

	log.Debugf("%s: %s", getKeepalivedScriptNotifyBackup(), buf.String())

	return nil
}

type KeepalivedConf struct {
	HeartBeatNic        string
	Interval            int
	MonitorIps          []string
	LocalIp             string
	LocalIpV6           string
	PeerIp              string
	PeerIpV6            string
	MasterScript        string
	BackupScript        string
	ScriptPath          string
	ScriptUser          string
	PrimaryBackupScript string
	Vips                []nicVipPair
	VipV4               *nicVipPair
	VipV6               *nicVipPair
	MaxAutoPriority     int 
}

func NewKeepalivedConf(hearbeatNic, LocalIp, LocalIpV6, PeerIp, PeerIpV6 string, MonitorIps []string, Interval int, vips []nicVipPair) *KeepalivedConf {
	var vipV4, vipV6 *nicVipPair
	if len(vips) == 2 {
		vipV4 = &vips[0]
		vipV6 = &vips[1]
	} else {
		if utils.IsIpv4Address(vips[0].Vip) {
			vipV4 = &vips[0]
		} else {
			vipV6 = &vips[0]
		}
	}

	kc := &KeepalivedConf{
		HeartBeatNic:        hearbeatNic,
		Interval:            Interval,
		MonitorIps:          MonitorIps,
		LocalIp:             LocalIp,
		LocalIpV6:           LocalIpV6,
		PeerIp:              PeerIp,
		PeerIpV6:            PeerIpV6,
		MasterScript:        getKeepalivedScriptNotifyMaster(),
		BackupScript:        getKeepalivedScriptNotifyBackup(),
		ScriptPath:          getKeepalivedScriptPath(),
		PrimaryBackupScript: getConntrackScriptPrimaryBackup(),
		ScriptUser:          utils.GetZvrUser(),
		Vips:                vips,
		VipV4:               vipV4,
		VipV6:               vipV6,
	}

	if utils.IsEuler2203() {
		kc.MaxAutoPriority = 99
	} else {
		kc.MaxAutoPriority = 0
		kc.ScriptUser = "root"
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
	script_user {{.ScriptUser}}
    enable_script_security
	{{ if ne .MaxAutoPriority 0 }}
	max_auto_priority  {{.MaxAutoPriority}}
	{{ end }}
}

vrrp_script monitor_zvr {
       script "{{.ScriptPath}}/check_zvr.sh"        # cheaper than pidof
       interval 2                      # check every 2 seconds
       fall 2                          # require 2 failures for KO
       rise 2                          # require 2 successes for OK
}

{{ range .MonitorIps }}
vrrp_script monitor_{{.}} {
	script "{{$.ScriptPath}}/check_monitor_{{.}}.sh"
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

const tKeepalivedSlbConf = `# This file is auto-generated, edit with caution!
global_defs {
	vrrp_garp_master_refresh 60
	vrrp_check_unicast_src
	script_user {{.ScriptUser}}
    enable_script_security
	{{ if ne .MaxAutoPriority 0 }}
	max_auto_priority  {{.MaxAutoPriority}}
	{{ end }}
}

vrrp_script monitor_zvr {
       script "{{.ScriptPath}}/check_zvr.sh"        # cheaper than pidof
       interval 2                      # check every 2 seconds
       fall 2                          # require 2 failures for KO
       rise 2                          # require 2 successes for OK
}

{{ range .MonitorIps }}
vrrp_script monitor_{{.}} {
	script "{{$.ScriptPath}}/check_monitor_{{.}}.sh"
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

{{ if .VipV4 }}
	unicast_src_ip {{.LocalIp}}
	unicast_peer {
		{{.PeerIp}}
	}
{{ else if .VipV6 }}
	unicast_src_ip {{.LocalIpV6}}
	unicast_peer {
		{{.PeerIpV6}}
	}
{{end}}

	track_script {
		monitor_zvr
{{ range .MonitorIps }}
                monitor_{{.}}
{{ end }}
	}
	virtual_ipaddress {
{{ range .Vips }}
            {{.Vip}}/{{.Prefix}}
{{ end }}
	}

	notify_master "{{.MasterScript}} MASTER"
	notify_backup "{{.BackupScript}} BACKUP"
}
`

const tKeepalivedSlbDualStackConf = `# This file is auto-generated, edit with caution!
global_defs {
	vrrp_garp_master_refresh 60
	vrrp_check_unicast_src
	script_user {{.ScriptUser}}
    enable_script_security
	{{ if ne .MaxAutoPriority 0 }}
	max_auto_priority  {{.MaxAutoPriority}}
	{{ end }}
}

vrrp_script monitor_zvr {
       script "{{.ScriptPath}}/check_zvr.sh"        # cheaper than pidof
       interval 2                      # check every 2 seconds
       fall 2                          # require 2 failures for KO
       rise 2                          # require 2 successes for OK
}

{{ range .MonitorIps }}
vrrp_script monitor_{{.}} {
	script "{{$.ScriptPath}}/check_monitor_{{.}}.sh"
	interval 2
	weight -2
	fall 3
	rise 3
}
{{ end }}

vrrp_sync_group vyos_group {
	group {
	  vyos-ha
	  vyos-ha-v6
	}
  }

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
	virtual_ipaddress {
            {{.VipV4.Vip}}/{{.VipV4.Prefix}}
	}

	notify_master "{{.MasterScript}} MASTER"
	notify_backup "{{.BackupScript}} BACKUP"
}

vrrp_instance vyos-ha-v6 {
	state BACKUP
	interface {{.HeartBeatNic}}
	virtual_router_id 50
	priority 100
	advert_int {{.Interval}}
	nopreempt

	unicast_src_ip {{.LocalIpV6}}
	unicast_peer {
		{{.PeerIpV6}}
	}

	track_script {
		monitor_zvr
{{ range .MonitorIps }}
                monitor_{{.}}
{{ end }}
	}
	virtual_ipaddress {
            {{.VipV6.Vip}}/{{.VipV6.Prefix}}
	}

	notify_master "{{.MasterScript}} MASTER"
	notify_backup "{{.BackupScript}} BACKUP"
}
`

func (k *KeepalivedConf) BuildCheckScript() error {
	check_zvr_tmp := `#! /bin/bash
sudo pidof %s > /dev/null
`
	zvr_bin := filepath.Join(utils.GetThirdPartyBinPath(), "zvr")
	check_zvr := fmt.Sprintf(check_zvr_tmp, zvr_bin)
	check_zvr_file := filepath.Join(getKeepalivedScriptPath(), "check_zvr.sh")
	if utils.IsEuler2203() {
		err := os.WriteFile(check_zvr_file, []byte(check_zvr), fs.FileMode(0700))
		utils.PanicOnError(err)
		utils.SetFileOwner(check_zvr_file, utils.GetZvrUser(), utils.GetZvrUser())
	} else {
		err := os.WriteFile(check_zvr_file, []byte(check_zvr), fs.FileMode(0644))
		utils.PanicOnError(err)
	}

	for _, ip := range k.MonitorIps {
		check_monitor := fmt.Sprintf("#! /bin/bash\nsudo /bin/ping %s -w 1 -c 1 > /dev/null", ip)
		script_name := fmt.Sprintf("/check_monitor_%s.sh", ip)
		check_monitor_file := filepath.Join(getKeepalivedScriptPath(), script_name)
		if utils.IsEuler2203() {
			err := os.WriteFile(check_monitor_file, []byte(check_monitor), 0700)
			utils.PanicOnError(err)
			utils.SetFileOwner(check_monitor_file, utils.GetZvrUser(), utils.GetZvrUser())
		} else {
			err := os.WriteFile(check_monitor_file, []byte(check_monitor), 0644)
			utils.PanicOnError(err)
		}
	}
	return nil
}

func (k *KeepalivedConf) BuildConf() error {
	tmpl, err := template.New("keepalived.conf").Parse(tKeepalivedConf)
	utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	err = os.WriteFile(getKeepalivedConfigFile(), buf.Bytes(), 0644)
	utils.PanicOnError(err)

	// generate conntrackd.conf
	buf.Reset()
	tmpl, err = template.New("conntrackd.conf").Parse(tConntrackdConf)
	utils.PanicOnError(err)
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)
	return os.WriteFile(getConntrackdConfigFile(), buf.Bytes(), 0644)
}


func doRestartKeepalived(action KeepAlivedProcessAction) error {
	if utils.IsEuler2203() {
		pid := getKeepalivedPid()
		if pid == PID_ERROR {
			os.Remove(KEEPALIVED_STATE_PATH)
			return utils.ServiceOperation("keepalived", "restart")
		}

		switch action {
		case KeepAlivedProcess_Restart:
			os.Remove(KEEPALIVED_STATE_PATH)
			return utils.ServiceOperation("keepalived", "restart")
		case KeepAlivedProcess_Reload:
			os.Remove(KEEPALIVED_STATE_PATH)
			return utils.ServiceOperation("keepalived", "reload")
		}

		return nil
	}

	/* # ./keepalived -h
		    Usage: ./keepalived [OPTION...]
	            -f, --use-file=FILE          Use the specified configuration file
	            -D, --log-detail             Detailed log messages
	            -S, --log-facility=[0-7]     Set syslog facility to LOG_LOCAL[0-7]
	*/
	pid := getKeepalivedPid()
	if pid == PID_ERROR {
		bash := utils.Bash{
			Command: fmt.Sprintf("sudo pkill -9 keepalived; sudo %s -D -S 2 -f %s -p %s", KeepalivedBinaryFile, getKeepalivedConfigFile(), KeepalivedPidFile),
		}
		bash.RunWithReturn()
		bash.PanicIfError()
	} else {
		/* keepalived is running, restart it only if force restart */
		switch action {
		case KeepAlivedProcess_Restart:
			bash := utils.Bash{
				Command: fmt.Sprintf("kill -TERM %d; %s -D -S 2 -f %s -p %s", pid, KeepalivedBinaryFile, getKeepalivedConfigFile(), KeepalivedPidFile),
				Sudo:    true,
			}
			return bash.Run()

		case KeepAlivedProcess_Reload:
			bash := utils.Bash{
				Command: fmt.Sprintf("sudo kill -HUP %d", pid),
			}
			return bash.Run()

		case KeepAlivedProcess_Skip:
		default:
			return nil
		}
	}

	return nil
}

func (k *KeepalivedConf) RestartKeepalived(action KeepAlivedProcessAction) error {
	return doRestartKeepalived(action)
}

func checkConntrackdRunning() {
	if getConntrackdPid() != PID_ERROR {
		return
	}

	bash := utils.Bash{
		Command: fmt.Sprintf("sudo %s -C %s -d", ConntrackdBinaryFile, getConntrackdConfigFile()),
	}

	bash.RunWithReturn()
}

func checkKeepalivedRunning() {
	pid := getKeepalivedPid()
	if pid == PID_ERROR {
		bash := utils.Bash{
			Command: fmt.Sprintf("sudo pkill -9 keepalived; sudo %s -D -S 2 -f %s -p %s", KeepalivedBinaryFile, getKeepalivedConfigFile(), KeepalivedPidFile),
		}

		bash.RunWithReturn()
	}

}

func callStatusChangeScripts() {
	var bash utils.Bash
	log.Debugf("!!! KeepAlived status change to %s", keepAlivedStatus.string())
	if keepAlivedStatus == KeepAlivedStatus_Master {
		bash = utils.Bash{
			Command: fmt.Sprintf("cat %s; %s MASTER", getKeepalivedScriptNotifyMaster(), getKeepalivedScriptNotifyMaster()),
		}
	} else if keepAlivedStatus == KeepAlivedStatus_Backup {
		bash = utils.Bash{
			Command: fmt.Sprintf("cat %s; %s BACKUP %d", getKeepalivedScriptNotifyBackup(), getKeepalivedScriptNotifyBackup(), server.CommandOptions.Port),
		}
	}
	bash.RunWithReturn()

	/* to avoid backup vpc nic up, we set nic disable state in zvrboot,
	   so when change to master state, delete the disable state */
	if keepAlivedStatus == KeepAlivedStatus_Master {
		nics, _ := utils.GetAllNics()

		if utils.IsEnableVyosCmd() {
			tree := server.NewParserFromShowConfiguration().Tree
			for _, nic := range nics {
				tree.Deletef("interfaces ethernet %s disable", nic.Name)
			}
			tree.Apply(false)
		} else {
			for _, nic := range nics {
				utils.IpLinkSetUp(nic.Name)
			}
		}
	}

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
	if utils.IsRuingUT() {
		return keepAlivedStatus
	}

	pid := getKeepalivedPid()
	if pid == PID_ERROR {
		log.Debugf("Error occurs while get keepalived pid, return keepalived status as unkdonw")
		return KeepAlivedStatus_Unknown
	}

	bash := utils.Bash{
		// There is race between generating keepalived.data and reading its content.
		Command: fmt.Sprintf("timeout 1 sudo kill -USR1 %d;sudo grep -A 6 'VRRP Topology' /tmp/keepalived.data | awk -F '=' '/State/{print $2}'",
			pid),
		NoLog: true,
	}

	ret, state, e, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		log.Debugf("get keepalived status %s", e)
	}
	
	switch strings.TrimSpace(string(state)) {
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
		err := exec.Command("sudo", "/bin/sh", getKeepalivedScriptMasterDoGARP()).Run()
		log.Debugf("master garp: %s", err)
		atomic.StoreUint32(&garp_counter, 0)
	}()

	return nil
}

const _zvr_shm = "/dev/shm/zvr.log"

func KeepalivedEntryPoint() {
	utils.RegisterDiskFullHandler(func(e error) {
		if utils.IsHaEnabled() && IsMaster() {
			s := time.Now().Format(time.RFC3339) + " " + e.Error() + "\n"
			os.WriteFile(_zvr_shm, []byte(s), 0640)
			doRestartKeepalived(KeepAlivedProcess_Restart)

			/* when disk is full, keepalived will restart and zvr process will exit, peer vpc will become the master vpc,
			   when keepalived start again, it will enter backup state, then call back script, but there are 2 issues:
			   1. peer become master, but current still has the master config, leads to traffic issue
			   2. because disk is full, keepalvied may start failed, it will not call backup script, so call it here */
			keepAlivedStatus = KeepAlivedStatus_Backup
			callStatusChangeScripts()
		}
	})

	server.RegisterSyncCommandHandler(KEEPALIVED_GARP_PATH, garpHandler)
}

func (k *KeepalivedConf) BuildSlbConf() error {
	var tmpl *template.Template
	var err error
	if len(k.Vips) == 2 {
		tmpl, err = template.New("keepalived.conf").Parse(tKeepalivedSlbDualStackConf)
	} else {
		tmpl, err = template.New("keepalived.conf").Parse(tKeepalivedSlbConf)
	}
	utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)

	err = os.WriteFile(getKeepalivedConfigFile(), buf.Bytes(), 0644)
	utils.PanicOnError(err)

	// generate conntrackd.conf
	buf.Reset()
	tmpl, err = template.New("conntrackd.conf").Parse(tConntrackdConf)
	utils.PanicOnError(err)
	err = tmpl.Execute(&buf, k)
	utils.PanicOnError(err)
	return os.WriteFile(getConntrackdConfigFile(), buf.Bytes(), 0644)
}

var keepAlivedStatus KeepAlivedStatus

func SetKeepalivedStatusForUt(status KeepAlivedStatus) {
	utils.SetHaStatus(utils.HABACKUP)
	keepAlivedStatus = status
}

func InitKeepalived() {
	os.Remove(_zvr_shm)
	os.Mkdir(getKeepalivedRootPath(), os.ModePerm)
	os.Mkdir(getKeepalivedConfigPath(), os.ModePerm)
	os.Mkdir(getKeepalivedScriptPath(), os.ModePerm)
	os.Remove(getKeepalivedScriptNotifyMaster())
	os.Remove(getKeepalivedScriptNotifyBackup())
}
