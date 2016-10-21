package plugin

import (
	"zvr/server"
	"fmt"
	"strings"
)

const (
	REMOVE_DNS_PATH = "/removedns"
	SET_DNS_PATH = "/setdns"
)

type dnsInfo struct {
	DnsAddress string `json:"dnsAddress"`
}

type setDnsCmd struct {
	Dns []dnsInfo `json:"dns"`
}

type removeDnsCmd struct {
	Dns []dnsInfo `json:"dns"`
}

func setDnsHandler(ctx *server.CommandContext) interface{} {
	vyos := server.NewParserFromShowConfiguration()

	cmd := &setDnsCmd{}
	ctx.GetCommand(cmd)

	commands := make([]string, 0)
	for _, info := range cmd.Dns {
		if _, ok := vyos.GetValue(fmt.Sprintf("service dns forwarding name-server %s", info.DnsAddress)); !ok {
			commands = append(commands, fmt.Sprintf("$SET service dns forwarding name-server %s", info.DnsAddress))
		}
	}

	if len(commands) != 0 {
		runVyosScript(strings.Join(commands, "\n"), nil)
	}

	return nil
}

func removeDnsHandler(ctx *server.CommandContext) interface{} {
	vyos := server.NewParserFromShowConfiguration()

	cmd := &removeDnsCmd{}
	ctx.GetCommand(cmd)

	commands := make([]string, 0)
	for _, info := range cmd.Dns {
		if _, ok := vyos.GetValue(fmt.Sprintf("service dns forwarding name-server %s", info.DnsAddress)); ok {
			commands = append(commands, fmt.Sprintf("$DELETE service dns forwarding name-server %s", info.DnsAddress))
		}
	}

	if len(commands) != 0 {
		runVyosScript(strings.Join(commands, "\n"), nil)
	}

	return nil
}

func DnsEntryPoint() {
	server.RegisterAsyncCommandHandler(SET_DNS_PATH, server.VyosLock(setDnsHandler))
	server.RegisterAsyncCommandHandler(REMOVE_DNS_PATH, server.VyosLock(removeDnsHandler))
}
