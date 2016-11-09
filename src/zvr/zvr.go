package main

import (
	"zvr/server"
	"zvr/plugin"
	"zvr/utils"
	"fmt"
	"flag"
	"os"
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
	tree := server.NewParserFromShowConfiguration().Tree

	tree.SetFirewallOnInterface("eth0", "local",
		fmt.Sprintf("destination address %v", options.Ip),
		fmt.Sprintf("destination port %v", options.Port),
		"protocol tcp",
		"action accept",
	)

	tree.Apply(false)
}

func main()  {
	parseCommandOptions()
	utils.InitLog(options.LogFile, false)
	loadPlugins()
	configureZvrFirewall()
	server.Start()
}