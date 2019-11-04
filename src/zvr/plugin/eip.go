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
	EipInfoMaxSize = 512
)

type eipInfo struct {
	VipIp string `json:"vipIp"`
	PrivateMac string `json:"privateMac"`
	GuestIp string `json:"guestIp"`
	PublicMac string `json:"publicMac"`
	SnatInboundTraffic bool `json:"snatInboundTraffic"`
	NeedCleanGuestIp bool `json:"needCleanGuestIp"`
}

var eipMap map[string]eipInfo

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

func makeEipDescriptionForGw(info eipInfo) string {
        return fmt.Sprintf("EIP-%v-%v-%v-gw", info.VipIp, info.GuestIp, info.PrivateMac)
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

func checkEipIpTableRules(eip eipInfo, addEip bool) error {
	/* the correct result of a Eip iptable nat rules:
	 *    # iptables-save  | grep 172.20.16.250
	 *	-A PREROUTING -d 172.20.16.250/32 -m comment --comment DST-NAT-1 -j DNAT --to-destination 10.86.4.132
	 *	-A POSTROUTING -s 10.86.4.132/32 -o eth0 -m comment --comment SRC-NAT-1 -j SNAT --to-source 172.20.16.250
	 */
	bash := &utils.Bash{
		Command: fmt.Sprintf("sudo iptables-save -t nat | grep -w %s ", eip.VipIp),
		NoLog: false,
	}
	ret, o, e, _ := bash.RunWithReturn()
	if (ret != 0 ) {
		/* this case should NOT happen */
		log.Debugf("check eip iptables rules: failed for %s, because %s", fmt.Sprintf("%+v", eip), e)
		return nil
	}

	o = strings.TrimSpace(o)
	lines := strings.Split(o, "\n")

	snatRule := false
	dnatRule := false
	for _, line := range lines {
		/* DNAT */
		if strings.Contains(line, "-j DNAT") && strings.Contains(line, eip.GuestIp){
			dnatRule = true
		}

		/* SNAT */
		if strings.Contains(line, "-j SNAT") && strings.Contains(line, fmt.Sprintf("%s/32", eip.GuestIp)){
			snatRule = true
		}
	}

	if (addEip) {
		if (dnatRule == true && snatRule == true) {
			return nil
		} else {
			return fmt.Errorf("check eip iptables rules: eip %s, stdout %s, err %s", fmt.Sprintf("%+v", eip), o, e)
		}
	} else {
		if (dnatRule == false && snatRule == false) {
			return nil
		} else {
			return fmt.Errorf("check eip iptables rules: eip %s, stdout %s, err %s", fmt.Sprintf("%+v", eip), o, e)
		}
	}
}

func setEip(tree *server.VyosConfigTree, eip eipInfo) {
	des := makeEipDescription(eip)
	nicname, err := utils.GetNicNameByMac(eip.PublicMac)
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

        if eip.SnatInboundTraffic {
                snatGwDes := makeEipDescriptionForGw(eip)
                gwip, err := utils.GetIpByNicName(prinicname); utils.PanicOnError(err)
                if r := tree.FindSnatRuleDescription(snatGwDes); r == nil {
                        tree.SetSnat(
                                fmt.Sprintf("description %v", snatGwDes),
                                fmt.Sprintf("outbound-interface %v", prinicname),
                                fmt.Sprintf("destination address %v", eip.GuestIp),
                                fmt.Sprintf("translation address %v", gwip),
                        )
                }
        }

	if r := tree.FindDnatRuleDescription(des); r == nil {
		tree.SetDnat(
			fmt.Sprintf("description %v", des),
			fmt.Sprintf("inbound-interface any"),
			fmt.Sprintf("destination address %v", eip.VipIp),
			fmt.Sprintf("translation address %v", eip.GuestIp),
		)
	}

	//create eipaddress group
	eipAddressGroup := "eip-group"
	tree.SetGroup("address", eipAddressGroup, eip.GuestIp)

	eipPubMacFirewallDes := "zstack-pub-eip-firewall-rule"
	eipPriMacFirewallDes := "zstack-pri-eip-firewall-rule"
	if r := tree.FindFirewallRuleByDescription(nicname, "in", eipPubMacFirewallDes); r == nil {
		tree.SetZStackFirewallRuleOnInterface(nicname, "behind","in",
			fmt.Sprintf("description %v", eipPubMacFirewallDes),
			fmt.Sprintf("destination group address-group %s", eipAddressGroup),
			"state new enable",
			"state established enable",
			"state related enable",
			"action accept",
		)

		tree.AttachFirewallToInterface(nicname, "in")

	}

	if r := tree.FindFirewallRuleByDescription(prinicname, "in", eipPriMacFirewallDes); r == nil {
		tree.SetZStackFirewallRuleOnInterface(prinicname, "behind", "in",
			fmt.Sprintf("description %v", eipPriMacFirewallDes),
			fmt.Sprintf("source group address-group %s", eipAddressGroup),
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
	eipAddressGroup := "eip-group"
	priDes := makeEipDescriptionForPrivateMac(eip)
	snatGwDes := makeEipDescriptionForGw(eip)
	nicname, err :=  utils.GetNicNameByMac(eip.PublicMac)
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

	if r := tree.FindSnatRuleDescription(snatGwDes); r != nil {
		r.Delete()
	}

	if r := tree.FindDnatRuleDescription(des); r != nil {
		r.Delete()
	}

	prinicname, err := utils.GetNicNameByMac(eip.PrivateMac); utils.PanicOnError(err)
	if r := tree.FindFirewallRuleByDescription(prinicname, "in", des); r != nil {
		r.Delete()
	}

	if r := tree.FindFirewallRuleByDescription(nicname, "in", des); r != nil {
		r.Delete()
	}

	if eip.NeedCleanGuestIp {
		if r := tree.FindGroupByName(eip.GuestIp, eipAddressGroup, "address"); r != nil {
			r.Delete()
		}
	}
}

func createEip(ctx *server.CommandContext) interface{} {
	cmd := &setEipCmd{}
	ctx.GetCommand(cmd)
	eip := cmd.Eip

	if utils.IsSkipVyosIptables() {
		eipMap[eip.VipIp] = eip
		syncEipByIptables()
		return nil
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		setEip(tree, eip)
		tree.Apply(false)

		err := checkEipIpTableRules(eip, true);
		if (err != nil) {
			/* rollback */
			deleteEip(tree, eip)
			tree.Apply(false)
			/* utils.PanicOnError(err) will response error message to ZStack, return value can not do it */
			utils.PanicOnError(err)
		}
		return err;
	}
}

func removeEip(ctx *server.CommandContext) interface{} {
	cmd := &removeEipCmd{}
	ctx.GetCommand(cmd)
	eip := cmd.Eip

	if utils.IsSkipVyosIptables() {
		delete(eipMap, eip.VipIp)
		syncEipByIptables()
	} else {
		err := utils.Retry(func() error {
			tree := server.NewParserFromShowConfiguration().Tree
			deleteEip(tree, eip)
			tree.Apply(false)

			return checkEipExists(eip);
		}, 3, 1); utils.LogError(err)
	}

	utils.CleanConnTrackConnection(eip.VipIp, "", 0)

	return nil
}

func syncEipByIptables() error {
	dnatRules := []utils.IptablesRule{}
	snatRules := []utils.IptablesRule{}
	filterRules := make(map[string][]utils.IptablesRule)
	for _, eip := range eipMap {
		/* nat rule */
		nicname, err := utils.GetNicNameByMac(eip.PublicMac)
		rule := utils.NewEipNatRule("", eip.VipIp, utils.DNAT, utils.EipRuleComment + eip.VipIp, "",  eip.GuestIp, 0)
		dnatRules = append(dnatRules, rule)

		rule = utils.NewEipNatRule(eip.GuestIp, "", utils.SNAT, utils.EipRuleComment + eip.VipIp, nicname,  eip.VipIp, 0)
		snatRules = append(snatRules, rule)

		prinicname, err := utils.GetNicNameByMac(eip.PrivateMac); utils.PanicOnError(err)

		if eip.SnatInboundTraffic {
			gwip, err := utils.GetIpByNicName(prinicname); utils.PanicOnError(err)
			rule = utils.NewEipNatRule("", eip.GuestIp, utils.SNAT, utils.EipRuleComment + eip.VipIp, prinicname, gwip, 0)
			snatRules = append(snatRules, rule)
		}

		/* firewall rule */
		rule = utils.NewIptablesRule("", "", eip.GuestIp, 0, 0, []string{utils.NEW, utils.RELATED, utils.ESTABLISHED},
			utils.RETURN, utils.EipRuleComment + eip.VipIp)
		filterRules[nicname] = append(filterRules[nicname], rule)
		rule = utils.NewIptablesRule("", eip.GuestIp, "", 0, 0, []string{utils.NEW, utils.RELATED, utils.ESTABLISHED},
			utils.RETURN, utils.EipRuleComment + eip.VipIp)
		filterRules[prinicname] = append(filterRules[prinicname], rule)
	}

	if err := utils.SyncNatRule(snatRules, dnatRules, utils.EipRuleComment); err != nil {
		log.Warn("SyncEipNatRule failed %s", err.Error())
		return err
	}

	if err := utils.SyncFirewallRule(filterRules, utils.EipRuleComment, utils.IN); err != nil {
		log.Warn("SyncEipFirewallRule failed %s", err.Error())
		return err
	}

	return nil
}

func syncEip(ctx *server.CommandContext) interface{} {
	cmd := &syncEipCmd{}
	ctx.GetCommand(cmd)

	eipMap = make(map[string]eipInfo, EipInfoMaxSize)
	if utils.IsSkipVyosIptables() {
		for _, eip := range cmd.Eips {
			eipMap[eip.VipIp] = eip
		}
		syncEipByIptables()
	} else {
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
	}

	for _, eip := range cmd.Eips {
		/* utils.PanicOnError(err) will response error message to ZStack, return value can not do it */
		err := checkEipIpTableRules(eip, true);utils.PanicOnError(err)
		/* even sync failed, ZStack will not remove eip configuration */
		if err != nil {
			return err
		}
	}

	return nil
}

func EipEntryPoint() {
	eipMap = make(map[string]eipInfo, EipInfoMaxSize)
	server.RegisterAsyncCommandHandler(VR_CREATE_EIP, server.VyosLock(createEip))
	server.RegisterAsyncCommandHandler(VR_REMOVE_EIP, server.VyosLock(removeEip))
	server.RegisterAsyncCommandHandler(VR_SYNC_EIP, server.VyosLock(syncEip))
}
