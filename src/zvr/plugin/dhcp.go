package plugin

import (
	"zvr"
	"github.com/pkg/errors"
	"fmt"
	"strings"
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

func addDhcpHandler(ctx *zvr.CommandContext) {
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
	parser := zvr.NewParserFromShowConfiguration()

	commands := make([]string, 0)
	for _, info := range infos {
		nicname, ok := zvr.FindNicNameByMac(info.VrNicMac)
		if !ok {
			panic(errors.Errorf("cannot find the nic with mac[%s] on the virtual router", info.VrNicMac))
		}

		netName := fmt.Sprintf("%s_subnet", nicname)
		_, ok = parser.GetValue(fmt.Sprintf("service dhcp-server shared-network-name %s authoritative", netName))
		if !ok {
			commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s authoritative enable", netName))
		}

		cidr, err := zvr.NetmaskToCIDR(info.Netmask)
		if err != nil {
			panic(err)
		}

		subnet := fmt.Sprintf("%s/%s", info.Ip, cidr)
		serverName := strings.Replace(info.Mac, ":", "_", -1)
		commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s subnet %s static-mapping %s ip-address %s",
			netName, subnet, serverName, info.Ip))
		commands = append(commands, fmt.Sprintf("$SET service dhcp-server shared-network-name %s subnet %s static-mapping %s mac-address %s",
			netName, subnet, serverName, strings.ToLower(info.Mac)))
	}
}

func rebuildAllDhcp(infos []dhcpInfo) {
}

func removeDhcpHandler(ctx *zvr.CommandContext) {
}

func init()  {
	zvr.RegisterAsyncCommandHandler(ADD_DHCP_PATH, addDhcpHandler)
	zvr.RegisterAsyncCommandHandler(REMOVE_DHCP_PATH, removeDhcpHandler)
}
