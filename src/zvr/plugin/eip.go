package plugin

import (
	"zvr/server"
	"fmt"
	"zvr/utils"
	"strings"
)

const (
	VR_CREATE_EIP = "/createeip"
	VR_REMOVE_EIP = "/removeeip"
	VR_SYNC_EIP = "/synceip"
)

type eipInfo struct {
	VipIp string `json:"vipIp"`
	PrivateMac string `json:"privateMac"`
	PublicMac string `json:"publicMac"`
	GuestIp string `json:"guestIp"`
	SnatInboundTraffic bool `json:"snatInboundTraffic"`
}

type setEipCmd struct {
	Eip eipInfo `json:"eip"`
}

type removeEipCmd struct {
	Eip eipInfo `json:"eip"`
}

type syncEipCmd struct {
	Eips []eipInfo `json:"eips"`
}

var EIP_SNAT_START_RULE_NUM = 5000

func makeEipDescription(info eipInfo) string {
	return fmt.Sprintf("EIP-%v-%v-%v", info.VipIp, info.GuestIp, info.PrivateMac)
}

func setEip(tree *server.VyosConfigTree, eip eipInfo) {
	des := makeEipDescription(eip)
	prinicname, err := utils.GetNicNameByMac(eip.PrivateMac); utils.PanicOnError(err)
	nicname, err := utils.GetNicNameByMac(eip.PublicMac); utils.PanicOnError(err)

	if r := tree.FindSnatRuleDescription(des); r == nil {
		tree.SetSnat(
			fmt.Sprintf("description %v", des),
			fmt.Sprintf("outbound-interface %v", nicname),
			fmt.Sprintf("source address %v", eip.GuestIp),
			fmt.Sprintf("translation address %v", eip.VipIp),
		)
	}

	if r := tree.FindDnatRuleDescription(des); r == nil {
		tree.SetDnat(
			fmt.Sprintf("description %v", des),
			fmt.Sprintf("inbound-interface any"),
			fmt.Sprintf("destination address %v", eip.VipIp),
			fmt.Sprintf("translation address %v", eip.GuestIp),
		)
	}

	if r := tree.FindFirewallRuleByDescription(nicname, "in", des); r == nil {
		tree.SetFirewallOnInterface(nicname, "in",
			fmt.Sprintf("description %v", des),
			fmt.Sprintf("destination address %v", eip.GuestIp),
			"state new enable",
			"state established enable",
			"state related enable",
			"action accept",
		)

		tree.AttachFirewallToInterface(nicname, "in")
	}

	if r := tree.FindFirewallRuleByDescription(prinicname, "in", des); r == nil {
		tree.SetFirewallOnInterface(prinicname, "in",
			fmt.Sprintf("description %v", des),
			fmt.Sprintf("source address %v", eip.GuestIp),
			"state new enable",
			"state established enable",
			"state related enable",
			"action accept",
		)

		tree.AttachFirewallToInterface(prinicname, "in")
	}
}

func deleteEip(tree *server.VyosConfigTree, eip eipInfo) {
	des := makeEipDescription(eip)
	nicname, err := utils.GetNicNameByIp(eip.VipIp); utils.PanicOnError(err)

	if r := tree.FindSnatRuleDescription(des); r != nil {
		r.Delete()
	}

	if r := tree.FindDnatRuleDescription(des); r != nil {
		r.Delete()
	}

	if r := tree.FindFirewallRuleByDescription(nicname, "in", des); r != nil {
		r.Delete()
	}

	prinicname, err := utils.GetNicNameByMac(eip.PrivateMac); utils.PanicOnError(err)
	if r := tree.FindFirewallRuleByDescription(prinicname, "in", des); r != nil {
		r.Delete()
	}
}

func createEip(ctx *server.CommandContext) interface{} {
	cmd := &setEipCmd{}
	ctx.GetCommand(cmd)
	eip := cmd.Eip

	tree := server.NewParserFromShowConfiguration().Tree
	setEip(tree, eip)
	tree.Apply(false)

	return nil
}

func removeEip(ctx *server.CommandContext) interface{} {
	cmd := &removeEipCmd{}
	ctx.GetCommand(cmd)
	eip := cmd.Eip

	tree := server.NewParserFromShowConfiguration().Tree
	deleteEip(tree, eip)
	tree.Apply(false)

	return nil
}

func syncEip(ctx *server.CommandContext) interface{} {
	cmd := &syncEipCmd{}
	ctx.GetCommand(cmd)

	tree := server.NewParserFromShowConfiguration().Tree

	// delete all EIP related rules
	if rs := tree.Get("nat destination rule"); rs != nil {
		for _, r := range rs.Children() {
			if d := r.Get("description"); d != nil && strings.HasPrefix(d.Value(), "EIP") {
				r.Delete()
			}
		}
	}

	if rs := tree.Getf("nat source rule"); rs != nil {
		for _, r := range rs.Children() {
			if d := r.Get("description"); d != nil && strings.HasPrefix(d.Value(), "EIP") {
				r.Delete()
			}
		}
	}

	if rs := tree.Getf("firewall name"); rs != nil {
		for _, r := range rs.Children() {
			if rss := r.Get("rule"); rss != nil {
				for _, rr := range rss.Children() {
					if d := rr.Get("description"); d != nil && strings.HasPrefix(d.Value(), "EIP") {
						rr.Delete()
					}
				}
			}
		}
	}

	for _, eip := range cmd.Eips {
		setEip(tree, eip)
	}

	tree.Apply(false)

	return nil
}

func EipEntryPoint() {
	server.RegisterAsyncCommandHandler(VR_CREATE_EIP, server.VyosLock(createEip))
	server.RegisterAsyncCommandHandler(VR_REMOVE_EIP, server.VyosLock(removeEip))
	server.RegisterAsyncCommandHandler(VR_SYNC_EIP, server.VyosLock(syncEip))
}
