package main

import (
	"zvr/server"
	"zvr/plugin"
	"zvr/utils"
	"fmt"
	"flag"
	"os"
	log "github.com/Sirupsen/logrus"
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

	parseCommandOptions()
	utils.InitLog(options.LogFile, false)
	utils.InitBootStrapInfo()
	plugin.InitHaNicState()
	utils.InitNatRule()
	loadPlugins()
	server.VyosLockInterface(configureZvrFirewall)()

	server.Start()
}
