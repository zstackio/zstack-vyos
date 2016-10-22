package main

import (
	"zvr/server"
	"zvr/plugin"
	"zvr/utils"
	"fmt"
	"strings"
	"flag"
	"os"
)

func loadPlugins()  {
	plugin.ApvmEntryPoint()
	plugin.DhcpEntryPoint()
	plugin.MiscEntryPoint()
	plugin.DnsEntryPoint()
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
	parser := server.NewParserFromShowConfiguration()

	commands := make([]string, 0)
	if _, ok := parser.GetConfig("firewall name zvr"); !ok {
		commands = append(commands, fmt.Sprintf("$SET firewall name zvr rule 1 destination port %v", options.Port))
		commands = append(commands, "$SET firewall name zvr rule 1 protocol tcp")
		commands = append(commands, "$SET firewall name zvr rule 1 action accept")
	}
	if _, ok := parser.GetValue("interfaces ethernet eth0 firewall local name zvr"); !ok {
		commands = append(commands, "$SET interfaces ethernet eth0 firewall local name zvr")
	}

	if len(commands) > 0 {
		server.RunVyosScriptAsUserVyos(strings.Join(commands, "\n"))
	}
}

func main()  {
	parseCommandOptions()
	utils.InitLog(options.LogFile, false)
	loadPlugins()
	configureZvrFirewall()
	server.Start()
}