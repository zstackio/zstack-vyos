package plugin

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"path/filepath"
	"zstack-vyos/utils"
)

var uacctd_conf_file = "/etc/pmacct/uacctd.conf"

func getUacctdBinFile() string {
	return filepath.Join(utils.GetThirdPartyBinPath(), "uacctd")
}

func getUacctdConfTmpFile() string {
	return filepath.Join(utils.GetUserHomePath(), "pmacct/pmacctd.conf.tmp")
}

const tUacctdConf = `# This file is auto-generated, don't edit with !!!
daemonize: true
pidfile:   /var/run/uacctd.pid
imt_path:  /tmp/uacctd.pipe
#pcap_interface: {{.NicsNamesStr}}
uacctd_group: 2
aggregate: src_mac,dst_mac,vlan,src_host,dst_host,src_port,dst_port,proto,tos,flows
syslog: daemon
plugins: memory,nfprobe
nfprobe_receiver: {{.CollectorIp}}:{{.CollectorPort}}
nfprobe_version: {{.Version}}
{{if eq .Version 5}}nfprobe_engine: {{.RouterId}}:0{{end}}
nfprobe_timeouts: general=3600:tcp.fin=300:tcp.rst=120:expint={{.ExpireInterval}}:tcp=3600:udp=300:icmp=300:maxlife={{.ActiveTimeout}}
sampling_rate: {{.SampleRate}}
`

func (fc *flowConfig) buildPmacctdConf() bool {
	tmpl, err := template.New("uacctdConf.conf").Parse(tUacctdConf)
	utils.PanicOnError(err)

	var buf bytes.Buffer
	fc.NicsNamesStr = strings.Join(fc.NicsNames, ",")
	err = tmpl.Execute(&buf, fc)
	utils.PanicOnError(err)

	err = ioutil.WriteFile(getUacctdConfTmpFile(), buf.Bytes(), 0644)
	utils.PanicOnError(err)
	checksumTemp, _ := getFileChecksum(getUacctdConfTmpFile())
	checksum, _ := getFileChecksum(uacctd_conf_file)

	log.Debugf("netflow old config file checksum %s, new config file checksum %s", checksum, checksumTemp)
	utils.SudoMoveFile(getUacctdConfTmpFile(), uacctd_conf_file)

	return strings.Compare(checksumTemp, checksum) != 0
}

func (fc *flowConfig) startPmacctdServers() {
	if len(fc.NicsNames) > 0 && fc.CollectorIp != "" {
		fc.setupFlowIpTables(true)
		changed := fc.buildPmacctdConf()
		if changed {
			bash := utils.Bash{
				Command: fmt.Sprintf("pkill -9 uacctd; %s -f %s -d", getUacctdBinFile(), uacctd_conf_file),
				Sudo:    true,
			}
			bash.Run()
			writeFlowHaScript(true)
		} else {
			log.Debugf("netflow config file not changed")
			if pid := getUacctdPid(); pid == PID_ERROR {
				bash := utils.Bash{
					Command: fmt.Sprintf("%s -f %s -d", getUacctdBinFile(), uacctd_conf_file),
					Sudo:    true,
				}
				bash.Run()
			}
		}
	} else {
		fc.setupFlowIpTables(false)
		bash := utils.Bash{
			Command: fmt.Sprintf("truncate -s 0 %s; pkill -9 uacctd", uacctd_conf_file),
			Sudo:    true,
		}
		bash.Run()
		writeFlowHaScript(false)
	}

	return
}

func (fc *flowConfig) setupFlowIpTables(enable bool) {
	if utils.Kernel_version == utils.Kernel_3_13_11 {
		setupFlowIpTablesForKernel3(fc.NicsNames, enable)
	} else {
		setupFlowIpTablesForKernel5_4_80(fc.NicsNames, enable)
	}
}

func setupFlowIpTablesForKernel3(nics []string, enable bool) {
	var cmds []string
	if enable {
		cmds = append(cmds, fmt.Sprintf("sudo iptables -t raw  -F VYATTA_CT_PREROUTING_HOOK"))
		for _, nicName := range nics {
			cmds = append(cmds, fmt.Sprintf("sudo iptables -t raw -A VYATTA_CT_PREROUTING_HOOK -i %s -j ULOG --ulog-nlgroup 2 "+
				"--ulog-cprange 64 --ulog-qthreshold 10", nicName))
		}
	} else {
		cmds = append(cmds, fmt.Sprintf("sudo iptables -t raw  -F VYATTA_CT_PREROUTING_HOOK"))
	}

	bash := utils.Bash{
		Command: strings.Join(cmds, ";"),
	}
	bash.Run()
}

func setupFlowIpTablesForKernel5_4_80(nics []string, enable bool) {
	var cmds []string
	if enable {
		cmds = append(cmds, fmt.Sprintf("sudo iptables -t raw  -F VYATTA_CT_PREROUTING_HOOK"))
		for _, nicName := range nics {
			cmds = append(cmds, fmt.Sprintf("sudo iptables -t raw -A VYATTA_CT_PREROUTING_HOOK -i %s -j NFLOG --nflog-group 2 "+
				"--nflog-range 64 --nflog-threshold 10", nicName))
		}
	} else {
		cmds = append(cmds, fmt.Sprintf("sudo iptables -t raw  -F VYATTA_CT_PREROUTING_HOOK"))
	}

	bash := utils.Bash{
		Command: strings.Join(cmds, ";"),
	}
	bash.Run()
}

func writeFlowHaScript(enable bool) {
	if !utils.IsHaEnabled() {
		return
	}

	var conent string
	if enable {
		conent = fmt.Sprintf("sudo pkill -9 uacctd; sudo %s -f %s", getUacctdBinFile(), uacctd_conf_file)
	} else {
		conent = fmt.Sprintf("sudo truncate -s 0 %s; sudo pkill -9 uacctd", uacctd_conf_file)
	}

	err := ioutil.WriteFile(getVyosHaFlowScript(), []byte(conent), 0755)
	utils.PanicOnError(err)
}

func getUacctdPid() int {
	stdout, err := exec.Command("pidof", "-x", getUacctdBinFile()).Output()
	if err != nil {
		log.Debugf("get uacctd pid failed %v", err)
		return PID_ERROR
	}

	/* when uacctd is running, the output will be: 3657, 3656, 3655
	   when uacctd not runing, the output will be empty */
	out := strings.TrimSpace(string(stdout))
	if out == "" {
		log.Debugf("uacctd is not running")
		return PID_ERROR
	}

	pids := strings.Fields(out)
	if n, err := strconv.Atoi(pids[len(pids)-1]); err != nil {
		log.Debugf("unexpected %s pid: %v", getUacctdBinFile(), pids)
		return PID_ERROR
	} else {
		return n
	}
}

func InitPmacctd() {
	utils.MkdirForFile(getUacctdConfTmpFile(), 0755)
}
