package plugin

import (
	"zvr/server"
	"zvr/utils"
	"fmt"
)

const (
	VR_CREATE_VIP = "/createvip"
	VR_REMOVE_VIP = "/removevip"
)

type vipInfo struct {
	Ip string `json:"ip"`
	Netmask string `json:"netmask"`
	Gateway string `json:"gateway"`
	OwnerEthernetMac string `json:"ownerEthernetMac"`
}

type setVipCmd struct {
	Vips []vipInfo `json:"vips"`
}

type removeVipCmd struct {
	Vips []vipInfo `json:"vips"`
}

func setVip(ctx *server.CommandContext) interface{} {
	cmd := &setVipCmd{}
	ctx.GetCommand(cmd)

	tree := server.NewParserFromShowConfiguration().Tree
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac); utils.PanicOnError(err)
		cidr, err := utils.NetmaskToCIDR(vip.Netmask); utils.PanicOnError(err)
		addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)
		if n := tree.Getf("interfaces ethernet %s address %v", nicname, addr); n == nil {
			tree.SetfWithoutCheckExisting("interfaces ethernet %s address %v", nicname, addr)
		}
	}

	tree.Apply(false)

	return nil
}

func removeVip(ctx *server.CommandContext) interface{} {
	cmd := &removeVipCmd{}
	ctx.GetCommand(cmd)

	tree := server.NewParserFromShowConfiguration().Tree
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac); utils.PanicOnError(err)
		cidr, err := utils.NetmaskToCIDR(vip.Netmask); utils.PanicOnError(err)
		addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)

		tree.Deletef("interfaces ethernet %s address %v", nicname, addr)
	}

	tree.Apply(false)

	return nil
}

func VipEntryPoint()  {
	server.RegisterAsyncCommandHandler(VR_CREATE_VIP, server.VyosLock(setVip))
	server.RegisterAsyncCommandHandler(VR_REMOVE_VIP, server.VyosLock(removeVip))
}
