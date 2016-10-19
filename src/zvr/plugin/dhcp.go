package plugin

import (
	"github.com/pkg/errors"
	"fmt"
	"strings"
	"zvr/utils"
	"zvr/server"
)

const (
	ADD_DHCP_PATH = "/adddhcp"
	REMOVE_DHCP_PATH = "/removedhcp"
)

type dhcpInfo struct {
	Ip string `json:"ip"`
	Mac string `json:"mac"`
	Netmask string `json:"netmask"`
	Gateway string `json:"gateway"`
	Dns []string `json:"dns"`
	Hostname string `json:"hostname"`
	VrNicMac string `json:"vrNicMac"`
	DnsDomain string `json:"dnsDomain"`
	IsDefaultL3Network bool `json:"isDefaultL3Network"`
}

type addDhcpCmd struct {
	DhcpEntries []dhcpInfo `json:"dhcpEntries"`
	rebuild bool `json:"rebuild"`
}

type removeDhcpCmd struct {
	DhcpEntries []dhcpInfo `json:"dhcpEntries"`
}

func addDhcpHandler(ctx *server.CommandContext) interface{} {
	cmd := &addDhcpCmd{}
	ctx.GetCommand(cmd)

	if cmd.rebuild {
		rebuildAllDhcp(cmd.DhcpEntries)
	} else {
		addDhcp(cmd.DhcpEntries)
	}

	return nil
}

func addDhcp(infos []dhcpInfo) {
	runVyosScript(strings.Join(makeDhcpCommands(infos), "\n"), nil)
}

func makeLanName(nicname string) string {
	return fmt.Sprintf("%s_subnet", nicname)
}

func makeServerName(mac string) string {
	return strings.Replace(mac, ":", "_", -1)
}

func makeDhcpCommands(infos []dhcpInfo) []string {
	parser := server.NewParserFromShowConfiguration()

	macs := make(map[string]dhcpInfo)
	for _, info := range infos {
		macs[info.VrNicMac] = info
	}

	subnetNames := make(map[string]string)
	commands := make([]string, 0)

	for vrMac, info := range macs {
		netName, subnet := infoToNetNameAndSubnet(info)
		subnetNames[vrMac] = netName

		_, ok := parser.GetValue(fmt.Sprintf("service dhcp-server shared-network-name %s authoritative", netName))
		if !ok {
			commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s authoritative enable", netName))
		}

		// DHCPD requires at least one lease rule in the configuration
		// We use the gateway as the default lease
		serverName := makeServerName(info.VrNicMac)
		_, ok = parser.GetValue(fmt.Sprintf("service dhcp-server shared-network-name %s subnet %s static-mapping %s ip-address",
			netName, subnet, serverName))
		if !ok {
			commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s subnet %s static-mapping %s ip-address %s",
				netName, subnet, serverName, info.Gateway))
		}

		_, ok = parser.GetValue(fmt.Sprintf("service dhcp-server shared-network-name %s subnet %s static-mapping %s mac-address",
			netName, subnet, serverName))
		if !ok {
			commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s subnet %s static-mapping %s mac-address %s",
				netName, subnet, serverName, info.VrNicMac))
		}
	}

	for _, info := range infos {
		netName := subnetNames[info.VrNicMac]
		subnet, err := utils.GetNetworkNumber(info.Ip, info.Netmask); utils.PanicOnError(err)
		serverName := makeServerName(info.Mac)
		commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s subnet %s static-mapping %s ip-address %s",
			netName, subnet, serverName, info.Ip))
		commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s subnet %s static-mapping %s mac-address %s",
			netName, subnet, serverName, strings.ToLower(info.Mac)))
		commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s subnet %s static-mapping %s static-mapping-parameters \"%s\"",
			netName, subnet, serverName, fmt.Sprintf("option option subnet-mask %s;", info.Netmask)))

		if info.IsDefaultL3Network {
			if info.Hostname != "" {
				commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s subnet %s static-mapping %s static-mapping-parameters \"%s\"",
					netName, subnet, serverName, fmt.Sprintf("option host-name &quot;%s&quot;;", info.Hostname)))
			}
			if info.Dns != nil {
				commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s subnet %s static-mapping %s static-mapping-parameters \"%s\"",
					netName, subnet, serverName, fmt.Sprintf("option domain-name-servers %s;", strings.Join(info.Dns, ","))))
			}
			if info.Gateway != "" {
				commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s subnet %s static-mapping %s static-mapping-parameters \"%s\"",
					netName, subnet, serverName, fmt.Sprintf("option routers %s;", info.Gateway)))
			}
			if info.DnsDomain != "" {
				commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s subnet %s static-mapping %s static-mapping-parameters \"%s\"",
					netName, subnet, serverName, fmt.Sprintf("option domain-name &quot;%s&quot;;", info.DnsDomain)))
			}
		}
	}

	return commands
}

func infoToNetNameAndSubnet(info dhcpInfo) (string, string) {
	nicname, ok := server.FindNicNameByMac(info.VrNicMac); utils.PanicIfError(ok, errors.Errorf("cannot find the nic with mac[%s] on the virtual router", info.VrNicMac))
	subnet, err := utils.GetNetworkNumber(info.Ip, info.Netmask); utils.PanicOnError(err)

	return makeLanName(nicname), subnet
}

func rebuildAllDhcp(infos []dhcpInfo) {
	commands := append(makeRemoveDhcpCommands(infos), makeDhcpCommands(infos)...)
	runVyosScript(strings.Join(commands, "\n"), nil)
}

func makeRemoveDhcpCommands(infos []dhcpInfo) []string {
	parser := server.NewParserFromShowConfiguration()
	commands := make([]string, 0)

	for _, info := range infos {
		netName, subnet := infoToNetNameAndSubnet(info)
		serverName := makeServerName(info.Mac)
		if _, ok := parser.GetConfig(fmt.Sprintf("service dhcp-server shared-network-name %s subnet %s static-mapping %s",
			netName, subnet, serverName)); ok {
			commands = append(commands, fmt.Sprintf("$DELETE service dhcp-server shared-network-name %s subnet %s static-mapping %s",
				netName, subnet, serverName))
		}
	}

	return commands
}

func removeDhcpHandler(ctx *server.CommandContext) interface{} {
	cmd := &removeDhcpCmd{}
	ctx.GetCommand(cmd)

	commands := makeRemoveDhcpCommands(cmd.DhcpEntries)
	if len(commands) != 0 {
		runVyosScript(strings.Join(commands, "\n"), nil)
	}

	return nil
}

var runVyosScript = func(script string, args map[string]string)  {
	server.RunVyosScript(script, args)
}

func init()  {
	server.RegisterAsyncCommandHandler(ADD_DHCP_PATH, addDhcpHandler)
	server.RegisterAsyncCommandHandler(REMOVE_DHCP_PATH, removeDhcpHandler)
}
