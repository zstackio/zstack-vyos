package main

import (
	"zvr/server"
	"zvr/plugin"
	"zvr/utils"
	"fmt"
	"strings"
)

func loadPlugins()  {
	plugin.DhcpEntryPoint()
	plugin.MiscEntryPoint()
	plugin.DnsEntryPoint()
}

var zvroptions server.Options

func configureZvrFirewall() {
	parser := server.NewParserFromShowConfiguration()

	commands := make([]string, 0)
	if _, ok := parser.GetConfig("firewall name zvr"); !ok {
		commands = append(commands, fmt.Sprintf("$SET firewall name zvr rule 1 destination port %v", zvroptions.Port))
		commands = append(commands, "$SET firewall name zvr rule 1 action accept")
	}
	if _, ok := parser.GetValue("interfaces ethernet eth0 firewall local name zvr"); !ok {
		commands = append(commands, "$SET interfaces ethernet eth0 firewall local name zvr")
	}

	if len(commands) > 0 {
		server.RunVyosScript(strings.Join(commands, "\n"), nil)
	}
}

func main()  {
	zvroptions = parseCommandOptions(7272)
	server.SetOptions(zvroptions)
	utils.InitLog(zvroptions.LogFile, false)
	loadPlugins()

	configureZvrFirewall()
	server.Start()
}