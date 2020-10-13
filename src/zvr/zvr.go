package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	log "github.com/Sirupsen/logrus"

	"zvr/plugin"
	"zvr/server"
	"zvr/utils"
)

func loadPlugins()  {
	plugin.ApvmEntryPoint()
	plugin.DhcpEntryPoint()
	plugin.MiscEntryPoint()
	plugin.DnsEntryPoint()
	plugin.SnatEntryPoint()
	plugin.DnatEntryPoint()
	plugin.VipEntryPoint()
	plugin.EipEntryPoint()
	plugin.LbEntryPoint()
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
}

func doLogRotate(fpath string) {
	exec.Command("/usr/sbin/logrotate", fpath).Run()
}

func setupRotates() {
	go func() {
		for {
			time.Sleep(time.Minute)
			for _, cfgfile := range(logfiles) {
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
	tree.Apply(false)
}

func main()  {
	restartRsyslog()
	parseCommandOptions()
	utils.InitLog(options.LogFile, false)
	utils.InitBootStrapInfo()
	utils.InitVyosVersion()
	plugin.InitHaNicState()
	utils.InitNatRule()
	loadPlugins()
	setupRotates()
	server.VyosLockInterface(configureZvrFirewall)()

	server.Start()
}
