package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/zstackio/zstack-vyos/plugin"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
)

func loadPlugins() {
	plugin.ApvmEntryPoint()
	plugin.DhcpEntryPoint()
	plugin.MiscEntryPoint()
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
}

// Note: there shouldn't be 'daily' etc. in the following config files.
var logfiles = []string{
	"/etc/logrotate.d/haproxy",
	"/etc/logrotate.d/cpu-monitor",
}

func doLogRotate(fpath string) {
	exec.Command("sudo", "/usr/sbin/logrotate", fpath).Run()
}

func setupRotates() {
	for _, cfgfile := range logfiles {
		utils.SetFileOwner(cfgfile, "root", "root")
	}

	go func() {
		for {
			time.Sleep(time.Minute)
			for _, cfgfile := range logfiles {
				doLogRotate(cfgfile)
			}
		}
	}()
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
		err := utils.InitNicFirewall("eth0", options.Ip, true, utils.ACCEPT)
		if err != nil {
			log.Debugf("zvr configureZvrFirewall failed %s", err.Error())
		}
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

func main() {
	parseCommandOptions()
	if st, err := utils.DiskUsage(getHeartBeatDir(options.LogFile)); err == nil && st.Avail == 0 {
		fmt.Fprintf(os.Stderr, "disk is full\n")
		os.Exit(1)
	}

	utils.InitLog(options.LogFile, false)
	utils.InitBootStrapInfo()
	utils.InitVyosVersion()
	plugin.InitHaNicState()
	utils.InitNatRule()
	loadPlugins()
	setupRotates()
	server.VyosLockInterface(configureZvrFirewall)()
	utils.StartDiskMon(getHeartBeatFile(options.LogFile), func(e error) { os.Exit(1) }, 2*time.Second)

	server.Start()
}
