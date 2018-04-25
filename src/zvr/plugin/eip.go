package plugin

import (
	"zvr/server"
	"fmt"
	"zvr/utils"
	"strings"
	log "github.com/Sirupsen/logrus"
)

const (
	VR_CREATE_EIP = "/createeip"
	VR_REMOVE_EIP = "/removeeip"
	VR_SYNC_EIP = "/synceip"
)

type eipInfo struct {
	VipIp string `json:"vipIp"`
	PrivateMac string `json:"privateMac"`
	GuestIp string `json:"guestIp"`
	PublicMac string `json:"publicMac"`
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

func makeEipDescriptionReg(info eipInfo) string {
	return fmt.Sprintf("^EIP-%v-", info.VipIp)
}

func makeEipDescriptionForPrivateMac(info eipInfo) string {
	return fmt.Sprintf("EIP-%v-%v-%v-private", info.VipIp, info.GuestIp, info.PrivateMac)
}

func cleanupOldEip(tree *server.VyosConfigTree, eip eipInfo) {
	desReg := makeEipDescriptionReg(eip)
	for i := 0; i < 1; {
		if r := tree.FindSnatRuleDescriptionRegex(desReg, utils.StringRegCompareFn); r != nil {
			r.Delete()
		} else {
			break
		}
	}
	for i := 0; i < 1; {
		if r := tree.FindDnatRuleDescriptionRegex(desReg, utils.StringRegCompareFn); r != nil {
			r.Delete()
		} else {
			break
		}
	}
	if nics, nicErr := utils.GetAllNics(); nicErr == nil {
		for _, val := range nics {
			for i := 0; i < 1; {
				if r := tree.FindFirewallRuleByDescriptionRegex(val.Name, "in", desReg, utils.StringRegCompareFn); r != nil {
					r.Delete()
				} else {
					break
				}
			}
		}
	}
}


func setEip(tree *server.VyosConfigTree, eip eipInfo) {
	des := makeEipDescription(eip)
	nicname, err := utils.GetNicNameByIp(eip.VipIp)
	if (nicname == "" || err != nil) && eip.PublicMac != "" {
		var nicname string
		err = utils.Retry(func() error {
			var e error
			nicname, e = utils.GetNicNameByMac(eip.PublicMac)
			if e != nil {
				return e
			} else if nicname == "" {
				return fmt.Errorf("empty nic name found for mac[%s]", eip.PublicMac)
			} else {
				return nil
			}
		}, 5, 1)
	}
	utils.PanicOnError(err)

	prinicname, err := utils.GetNicNameByMac(eip.PrivateMac); utils.PanicOnError(err)

	/* delete old rule in case deleted failed when delete EIP */
	cleanupOldEip(tree, eip)

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

func checkEipExists(eip eipInfo) error {
	tree := server.NewParserFromShowConfiguration().Tree
	des := makeEipDescription(eip)
	priDes := makeEipDescriptionForPrivateMac(eip)

	if r := tree.FindSnatRuleDescription(des); r != nil {
		return fmt.Errorf("%s snat deletion fail", des)
	}

	if r := tree.FindSnatRuleDescription(priDes); r != nil {
		return fmt.Errorf("%s snat deletion fail", priDes)
	}

	if r := tree.FindDnatRuleDescription(des); r != nil {
		return fmt.Errorf("%s dnat deletion fail", des)
	}

	log.Debugf("checkEipExists %v des %s priDes %s successfuuly deleted", eip, des, priDes)

	return nil
}

func deleteEip(tree *server.VyosConfigTree, eip eipInfo) {
	des := makeEipDescription(eip)
	priDes := makeEipDescriptionForPrivateMac(eip)
	nicname, err := utils.GetNicNameByIp(eip.VipIp)
	if err != nil && eip.PublicMac != "" {
		var nicname string
		err = utils.Retry(func() error {
			var e error
			nicname, e = utils.GetNicNameByMac(eip.PublicMac)
			if e != nil {
				return e
			} else {
				return nil
			}
		}, 5, 1)
	}
	utils.PanicOnError(err)


	if r := tree.FindSnatRuleDescription(des); r != nil {
		r.Delete()
	}

	if r := tree.FindSnatRuleDescription(priDes); r != nil {
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

	err := utils.Retry(func() error {
                tree := server.NewParserFromShowConfiguration().Tree
                deleteEip(tree, eip)
                tree.Apply(false)

                return checkEipExists(eip);
        }, 3, 1); utils.LogError(err)
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
