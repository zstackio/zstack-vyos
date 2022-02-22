package plugin

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
	"strings"
)

const (
	VR_CREATE_EIP  = "/createeip"
	VR_REMOVE_EIP  = "/removeeip"
	VR_SYNC_EIP    = "/synceip"
	EipInfoMaxSize = 512
	EIP_IPSET_NAME = "eip-group"
)

type eipInfo struct {
	VipIp              string `json:"vipIp"`
	PrivateMac         string `json:"privateMac"`
	GuestIp            string `json:"guestIp"`
	PublicMac          string `json:"publicMac"`
	SnatInboundTraffic bool   `json:"snatInboundTraffic"`
	NeedCleanGuestIp   bool   `json:"needCleanGuestIp"`
}

var eipMap map[string]eipInfo
var eipIpset *utils.IpSet

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

func checkEipIpTableRules(eip eipInfo) error {
	natTable := utils.NewIpTables(utils.NatTable)
	nicName, err := utils.GetNicNameByMac(eip.PublicMac)
	if err != nil {
		return err
	}

	rule := utils.NewIpTableRule(utils.RULESET_DNAT.String())
	rule.SetAction(utils.IPTABLES_ACTION_DNAT)
	rule.SetDstIp(eip.VipIp + "/32").SetDnatTargetIp(eip.GuestIp)
	if natTable.Check(rule) == false {
		return fmt.Errorf("dnat rule[%s] check failed", rule.String())
	}

	rule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
	rule.SetAction(utils.IPTABLES_ACTION_SNAT)
	rule.SetOutNic(nicName).SetSrcIp(eip.GuestIp + "/32").SetSnatTargetIp(eip.VipIp)
	if natTable.Check(rule) == false {
		return fmt.Errorf("snat rule[%s] check failed", rule.String())
	}

	return nil
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

	prinicname, err := utils.GetNicNameByMac(eip.PrivateMac)
	utils.PanicOnError(err)

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
		gwip, err := utils.GetIpByNicName(prinicname)
		utils.PanicOnError(err)
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
		tree.SetZStackFirewallRuleOnInterface(nicname, "behind", "in",
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
	nicname, err := utils.GetNicNameByMac(eip.PublicMac)
	if err != nil && eip.PublicMac != "" {
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

	prinicname, err := utils.GetNicNameByMac(eip.PrivateMac)
	utils.PanicOnError(err)
	if r := tree.FindFirewallRuleByDescription(prinicname, "in", des); r != nil {
		r.Delete()
	}

	if r := tree.FindFirewallRuleByDescription(nicname, "in", des); r != nil {
		r.Delete()
	}

	cleanAddressGroup := true
	rules := tree.Get("nat source rule")
	if rules != nil {
		for _, r := range rules.Children() {
			guestIp := r.Get("source address")
			if guestIp != nil && guestIp.Value() == eip.GuestIp {
				cleanAddressGroup = false
				break
			}
		}
	}

	if cleanAddressGroup {
		if r := tree.FindGroupByNameValue(eip.GuestIp, eipAddressGroup, "address"); r != nil {
			r.Delete()
		}
	}
}

func createEipHandler(ctx *server.CommandContext) interface{} {
	cmd := &setEipCmd{}
	ctx.GetCommand(cmd)

	return createEip(cmd)
}

func createEip(cmd *setEipCmd) interface{} {
	eip := cmd.Eip

	if utils.IsSkipVyosIptables() {
		eipMap[eip.VipIp] = eip
		if err := syncEipByIptables(); err != nil {
			panic(err)
		}
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		setEip(tree, eip)
		tree.Apply(false)

		err := checkEipIpTableRules(eip)
		if err != nil {
			/* rollback */
			//deleteEip(tree, eip)
			tree.Apply(false)
			/* utils.PanicOnError(err) will response error message to ZStack, return value can not do it */
			utils.PanicOnError(err)
		}
	}

	/* before eip is enabled, delete existed connection */
	t := utils.ConnectionTrackTuple{IsNat: false, IsDst: true, Ip: eip.VipIp, Protocol: "", PortStart: 0, PortEnd: 0}
	t.CleanConnTrackConnection()

	return nil
}

func removeEipHandler(ctx *server.CommandContext) interface{} {
	cmd := &removeEipCmd{}
	ctx.GetCommand(cmd)

	return removeEip(cmd)
}

func removeEip(cmd *removeEipCmd) interface{} {
	eip := cmd.Eip

	if utils.IsSkipVyosIptables() {
		delete(eipMap, eip.VipIp)
		if err := syncEipByIptables(); err != nil {
			panic(err)
		}
	} else {
		err := utils.Retry(func() error {
			tree := server.NewParserFromShowConfiguration().Tree
			deleteEip(tree, eip)
			tree.Apply(false)

			return checkEipExists(eip)
		}, 3, 1)
		utils.LogError(err)
	}

	/* before eip is disabled, delete existed connections */
	t := utils.ConnectionTrackTuple{IsNat: false, IsDst: true, Ip: eip.VipIp, Protocol: "", PortStart: 0, PortEnd: 0}
	t.CleanConnTrackConnection()
	t = utils.ConnectionTrackTuple{IsNat: false, IsDst: false, Ip: eip.GuestIp, Protocol: "", PortStart: 0, PortEnd: 0}
	t.CleanConnTrackConnection()

	return nil
}

func syncEipByIptables() error {
	if eipIpset == nil {
		eipIpset = utils.NewIPSet(EIP_IPSET_NAME, utils.IPSET_TYPE_HASH_IP)
		if err := eipIpset.Create(); err != nil {
			log.Debugf("create eip ipset failed %s", err)
			return err
		}
	}
	ipsetMemberMap := make(map[string]string)
	guestIpMap := make(map[string]string)
	for _, member := range eipIpset.Member {
		ipsetMemberMap[member] = member
	}

	var toAddMemeber []string
	var toDelMemeber []string
	for _, eip := range eipMap {
		if _, ok := ipsetMemberMap[eip.GuestIp]; !ok {
			toAddMemeber = append(toAddMemeber, eip.GuestIp)
		}
		guestIpMap[eip.GuestIp] = eip.GuestIp
	}
	for _, member := range eipIpset.Member {
		if _, ok := guestIpMap[member]; !ok {
			toDelMemeber = append(toDelMemeber, member)
		}
	}

	if len(toAddMemeber) != 0 {
		if err := eipIpset.AddMember(toAddMemeber); err != nil {
			log.Debugf("add member %s to eip ipset failed %v", toAddMemeber, err)
			return err
		}
	}

	if len(toDelMemeber) != 0 {
		if err := eipIpset.DeleteMember(toDelMemeber); err != nil {
			log.Debugf("remove member %s from eip ipset failed %v", toDelMemeber, err)
			return err
		}
	}

	table := utils.NewIpTables(utils.FirewallTable)
	natTable := utils.NewIpTables(utils.NatTable)
	table.RemoveIpTableRuleByComments(utils.EipRuleComment)
	natTable.RemoveIpTableRuleByComments(utils.EipRuleComment)

	var natRules []*utils.IpTableRule
	var filterRule []*utils.IpTableRule

	for _, eip := range eipMap {
		/* nat rule */
		nicname, err := utils.GetNicNameByMac(eip.PublicMac)
		rule := utils.NewIpTableRule(utils.RULESET_DNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_DNAT).SetComment(utils.EipRuleComment)
		rule.SetDstIp(eip.VipIp + "/32").SetDnatTargetIp(eip.GuestIp)
		rule.SetCompareTarget(true)
		natRules = append(natRules, rule)

		rule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.EipRuleComment)
		rule.SetOutNic(nicname).SetSrcIp(eip.GuestIp + "/32").SetSnatTargetIp(eip.VipIp)
		rule.SetCompareTarget(true)
		natRules = append(natRules, rule)

		prinicname, err := utils.GetNicNameByMac(eip.PrivateMac)
		utils.PanicOnError(err)

		if eip.SnatInboundTraffic {
			gwip, err := utils.GetIpByNicName(prinicname)
			utils.PanicOnError(err)

			rule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
			rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.EipRuleComment)
			rule.SetOutNic(prinicname).SetDstIp(eip.GuestIp + "/32").SetSnatTargetIp(gwip)
			natRules = append(natRules, rule)
		}

		/* firewall rule */
		rule = utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_IN))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.EipRuleComment)
		rule.SetDstIpset(EIP_IPSET_NAME).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
		filterRule = append(filterRule, rule)

		rule = utils.NewIpTableRule(utils.GetRuleSetName(prinicname, utils.RULESET_IN))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.EipRuleComment)
		rule.SetSrcIpset(EIP_IPSET_NAME).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
		filterRule = append(filterRule, rule)
	}

	table.AddIpTableRules(filterRule)
	err := table.Apply()
	utils.PanicOnError(err)

	natTable.AddIpTableRules(natRules)
	err = natTable.Apply()
	utils.PanicOnError(err)

	return nil
}

func syncEipHandler(ctx *server.CommandContext) interface{} {
	cmd := &syncEipCmd{}
	ctx.GetCommand(cmd)

	return syncEip(cmd)
}

func syncEip(cmd *syncEipCmd) interface{} {
	eipMap = make(map[string]eipInfo, EipInfoMaxSize)
	if utils.IsSkipVyosIptables() {
		for _, eip := range cmd.Eips {
			eipMap[eip.VipIp] = eip
		}
		err := syncEipByIptables()
		utils.PanicOnError(err)
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
		if err := checkEipIpTableRules(eip); err != nil {
			return err
		}
	}

	return nil
}

func EipEntryPoint() {
	eipMap = make(map[string]eipInfo, EipInfoMaxSize)
	eipIpset = nil
	ipsets, _ := utils.GetCurrentIpSet()
	for _, ipset := range ipsets {
		if ipset.Name == EIP_IPSET_NAME {
			eipIpset = ipset
			break
		}
	}

	server.RegisterAsyncCommandHandler(VR_CREATE_EIP, server.VyosLock(createEipHandler))
	server.RegisterAsyncCommandHandler(VR_REMOVE_EIP, server.VyosLock(removeEipHandler))
	server.RegisterAsyncCommandHandler(VR_SYNC_EIP, server.VyosLock(syncEipHandler))
}
