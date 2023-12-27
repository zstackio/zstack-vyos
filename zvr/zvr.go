package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/pkg/errors"
	"github.com/zstackio/zstack-vyos/plugin"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
)

func loadPlugins() {
	plugin.ApvmEntryPoint()
	plugin.DhcpEntryPoint()
	plugin.DnsEntryPoint()
	plugin.SnatEntryPoint()
	plugin.DnatEntryPoint()
	plugin.VipEntryPoint()
	plugin.EipEntryPoint()
	plugin.LbEntryPoint()
	plugin.KeepalivedEntryPoint()
	plugin.IPsecEntryPoint()
	plugin.ConfigureNicEntryPoint()
	plugin.RouteEntryPoint()
	plugin.ZsnEntryPoint()
	plugin.PrometheusEntryPoint()
	plugin.OspfEntryPoint()
	plugin.VyosHaEntryPoint()
	plugin.FlowMeterEntryPoint()
	plugin.PolicyRouteEntryPoint()
	plugin.PimdEntryPoint()
	plugin.FirewallEntryPoint()
	plugin.PerformanceEntryPoint()
	plugin.MiscEntryPoint()
}

func initPlugins() {
	if err := plugin.IpsecInit(); err != nil {
		log.Warningf("init plugin ipsec failed, %v", err.Error())
	}
	plugin.InitHaNicState()
}

type nic struct {
	ip       string
	name     string
	category string
}

var zvrHomePath     = utils.GetUserHomePath()
var zvrRootPath     = utils.GetZvrRootPath()
var zvrZsConfigPath = utils.GetZvrZsConfigPath()

// Note: there shouldn't be 'daily' etc. in the following config files.
var logfiles = []string{
	"/etc/logrotate.d/haproxy",
	"/etc/logrotate.d/cpu-monitor",
	"/etc/logrotate.d/mail-monitor",
}

var logrotateFolder string = "/etc/logrotate.d/"

func doLogRotate(fpath string) {
	exec.Command("sudo", "/usr/sbin/logrotate", fpath).Run()
}

func setJournalLogRotate() {
	journaldConfigPath := "/etc/systemd/journald.conf"
	journalLogDirExist, _ := utils.PathExists("/var/log/journal")
	journalConfigExist, _ := utils.PathExists(journaldConfigPath)
	if (journalLogDirExist == false) || (journalConfigExist == false) {
		//No need to set journal log rotate
		return
	}
	journaldConfFile, err := ioutil.TempFile("/tmp", "tmpJournald.conf")
	utils.PanicOnError(err)
	journalConf := `[Journal]
Storage=none
ForwardToSyslog=yes
MaxLevelSyslog=debug
`

	_, err = journaldConfFile.Write([]byte(journalConf))
	utils.PanicOnError(err)

	utils.SudoMoveFile(journaldConfFile.Name(), journaldConfigPath)
	utils.SetFileOwner(journaldConfigPath, "root", "root")
	exec.Command("sudo", "journalctl", "--vacuum-size=50M").Run()
	exec.Command("sudo", "systemctl", "restart", "systemd-journald").Run()
}

func setupRotates() {
	utils.SetFolderOwner(logrotateFolder, "root", "root")
	go setJournalLogRotate()

	go func() {
		if utils.IsRuingUT() {
			return
		}

		for {
			time.Sleep(time.Minute)
			for _, cfgfile := range logfiles {
				doLogRotate(cfgfile)
			}
		}
	}()
}

func restartRsyslog() {
	exec.Command("sudo", "/etc/init.d/rsyslog", "restart").Run()
}

var options server.Options

func abortOnWrongOption(msg string) {
	fmt.Println(msg)
	flag.Usage()
	os.Exit(1)
}

func parseCommandOptions() {
	options = server.Options{}
	flag.StringVar(&options.Ip, "ip", "", "The IP address the server listens on")
	flag.UintVar(&options.Port, "port", 7272, "The port the server listens on")
	flag.UintVar(&options.ReadTimeout, "readtimeout", 10, "The socket read timeout")
	flag.UintVar(&options.WriteTimeout, "writetimeout", 10, "The socket write timeout")
	flag.StringVar(&options.LogFile, "logfile", "zvr.log", "The log file path")

	flag.Parse()

	if options.Ip == "" {
		abortOnWrongOption("error: the options 'ip' is required")
	}

	server.SetOptions(options)
}

func configureZvrFirewall() {
	if utils.IsSkipVyosIptables() {
		return
	}

	tree := server.NewParserFromShowConfiguration().Tree

	/* add description to avoid duplicated firewall rule when reconnect vr */
	des := "management-port-rule"
	if r := tree.FindFirewallRuleByDescription("eth0", "local", des); r != nil {
		r.Delete()
		/* if error happened, make sure zvr can work properly,
		   firewall for 7272 need to be delete and added back
		  tree.Apply(false) */
	}

	tree.SetFirewallOnInterface("eth0", "local",
		fmt.Sprintf("destination address %v", options.Ip),
		fmt.Sprintf("destination port %v", options.Port),
		"protocol tcp",
		"action accept",
		fmt.Sprintf("description %s", des),
	)
	tree.Apply(true)
}

func getHeartBeatDir(fpath string) string {
	if p, err := filepath.Abs(fpath); err != nil {
		return os.Getenv("HOME")
	} else {
		return filepath.Dir(p)
	}
}

func getHeartBeatFile(fpath string) string {
	dir := getHeartBeatDir(fpath)
	return filepath.Join(dir, ".zvr.diskmon")
}

func deleteRemainingIptableRules() {
	natTable := utils.NewIpTables(utils.NatTable)
	table := utils.NewIpTables(utils.FirewallTable)

	natTable.DeleteChainByKey("zs.")
	table.DeleteChainByKey(".zs.")

	var rules []*utils.IpTableRule
	for _, r := range table.Rules {
		if !strings.Contains(r.GetAction(), ".zs.") && !strings.Contains(r.GetChainName(), ".zs.") {
			rules = append(rules, r)
		}
	}
	table.Rules = rules

	var natRules []*utils.IpTableRule
	for _, r := range natTable.Rules {
		if !strings.Contains(r.GetAction(), "zs.") && !strings.Contains(r.GetChainName(), "zs.") {
			natRules = append(natRules, r)
		}
	}
	natTable.Rules = natRules

	err := table.Apply()
	if err != nil {
		log.Debugf("Delete remaining filter iptables rule failed, %v", err.Error())
	}

	err = natTable.Apply()
	if err != nil {
		log.Debugf("Delete remaining nat iptables rule failed, %v", err.Error())
	}

	/*flush raw table to clear NOTRACK rule at startup*/
	cmd := utils.Bash{
		Command: "sudo iptables -t raw -D PREROUTING -p vrrp -j NOTRACK;" +
			"sudo iptables -t raw -D OUTPUT -p vrrp -j NOTRACK",
	}
	_, _, _, err = cmd.RunWithReturn()
	if err != nil {
		log.Debugf("Delete remaining raw iptables rule failed, %v", err.Error())
	}
}

func checkIptablesRules() {
	if !utils.IsSkipVyosIptables() {
		return
	}

	table := utils.NewIpTables(utils.FirewallTable)
	//low version will create ethx.zs.local chain if configure firewall with iptables
	if !table.CheckChain("eth0.zs.local") {
		return
	}

	deleteRemainingIptableRules()

	var nics map[string]*nic = make(map[string]*nic)
	mgmtNic := utils.BootstrapInfo["managementNic"].(map[string]interface{})
	if mgmtNic == nil {
		panic(errors.New("no field 'managementNic' in bootstrap info"))
	}

	eth0 := &nic{name: "eth0"}
	var ok bool
	eth0.ip, ok = mgmtNic["ip"].(string)
	_, ok = mgmtNic["ip"].(string)
	_, ok6 := mgmtNic["ip6"].(string)
	utils.PanicIfError(ok || ok6, fmt.Errorf("cannot find 'ip' field for the nic[name:%s]", eth0.name))

	if mgmtNic["l2type"] != nil {
		eth0.category = mgmtNic["category"].(string)
	}

	nics[eth0.name] = eth0

	otherNics := utils.BootstrapInfo["additionalNics"].([]interface{})
	if otherNics != nil {
		for _, o := range otherNics {
			onic := o.(map[string]interface{})
			n := &nic{}
			n.name, ok = onic["deviceName"].(string)
			utils.PanicIfError(ok, fmt.Errorf("cannot find 'deviceName' field for the nic"))

			n.ip, ok = onic["ip"].(string)
			_, ok := onic["ip"].(string)
			_, ok6 := onic["ip6"].(string)
			utils.PanicIfError(ok || ok6, fmt.Errorf("cannot find 'ip' field for the nic[name:%s]", n.name))

			if onic["l2type"] != nil {
				n.category = onic["category"].(string)
			}

			nics[n.name] = n
		}
	}

	for _, nic := range nics {
		var err error
		if nic.category == "Private" {
			err = utils.InitNicFirewall(nic.name, nic.ip, false, utils.IPTABLES_ACTION_REJECT)
		} else {
			err = utils.InitNicFirewall(nic.name, nic.ip, true, utils.IPTABLES_ACTION_REJECT)
		}
		if err != nil {
			log.Debugf("InitNicFirewall for nic: %s failed", err.Error())
		}
	}
}

func main() {
	parseCommandOptions()
	if st, err := utils.DiskUsage(getHeartBeatDir(options.LogFile)); err == nil && st.Avail == 0 {
		fmt.Fprintf(os.Stderr, "disk is full\n")
		os.Exit(1)
	}

	go restartRsyslog()
	utils.InitLog(options.LogFile, false)
	utils.InitBootStrapInfo()
	utils.InitVyosVersion()
	checkIptablesRules()
	utils.InitNatRule()
	initPlugins()
	loadPlugins()
	setupRotates()
	server.VyosLockInterface(configureZvrFirewall)()
	utils.StartDiskMon(getHeartBeatFile(options.LogFile), func(e error) { if utils.IsHaEnabled() {os.Exit(1)} }, 2*time.Second)

	server.Start()
}
