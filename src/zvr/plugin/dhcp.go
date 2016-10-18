package plugin

import (
	"zvr"
	"github.com/pkg/errors"
	"fmt"
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
	for _, info := range infos {
		nicname, ok := zvr.FindNicNameByMac(info.VrNicMac)
		if !ok {
			panic(errors.Errorf("cannot find the nic with mac[%s] on the virtual router", info.VrNicMac))
		}

		subnetName := fmt.Sprintf("%s_subnet", nicname)
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
