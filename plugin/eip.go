package plugin

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"strings"
	"zstack-vyos/server"
	"zstack-vyos/utils"
)

const (
	VR_CREATE_EIP       = "/createeip"
	VR_REMOVE_EIP       = "/removeeip"
	VR_SYNC_EIP         = "/synceip"
	EipInfoMaxSize      = 512
	EIP_IPSET_NAME      = "eip-group"
	EIP_IPV6_IPSET_NAME = "eip-ipv6-group"

	IP_VERSION_4 = "ipv4"
	IP_VERSION_6 = "ipv6"
)

type eipInfo struct {
	VipIp              string `json:"vipIp"`
	PrivateMac         string `json:"privateMac"`
	GuestIp            string `json:"guestIp"`
	PublicMac          string `json:"publicMac"`
	SnatInboundTraffic bool   `json:"snatInboundTraffic"`
	NeedCleanGuestIp   bool   `json:"needCleanGuestIp"`
	IpVersion          string `json:"ipVersion"`
}

var eipMap map[string]eipInfo
var eipIpset *utils.IpSet
var eipIpv6Ipset *utils.IpSet

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

func checkEipIpTableRules(eipList []eipInfo) error {
	natTable := utils.NewIpTables(utils.NatTable)

	for _, eip := range eipList {
		nicName, err := utils.GetNicNameByMac(eip.PublicMac)
		if err != nil {
			return err
		}
		if eip.IpVersion == IP_VERSION_6 {
			return fmt.Errorf("checkEipIpTableRules: ipv6 not support with VyOS, use openEuler upgrade it")
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
		for _, e := range eipMap {
			if e.IpVersion == IP_VERSION_6 && utils.IsVYOS() {
				utils.PanicOnError(fmt.Errorf("attach eip ipv6 not support with VyOS, use openEuler upgrade it"))
			}
		}
		if err := syncEipByIptables(); err != nil {
			utils.PanicOnError(err)
		}
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		setEip(tree, eip)
		tree.Apply(false)

		if err := checkEipIpTableRules([]eipInfo{eip}); err != nil {
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
			utils.PanicOnError(err)
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
	if eipIpv6Ipset == nil && !utils.IsVYOS() {
		eipIpv6Ipset = utils.NewIPSetByFamily(EIP_IPV6_IPSET_NAME, utils.IPSET_TYPE_HASH_IP, utils.IPSET_FAMILY_INET6)
		if err := eipIpv6Ipset.Create(); err != nil {
			log.Debugf("create eip ipv6 ipset failed %s", err)
			return err
		}
	}

	ipsetMemberMap := make(map[string]string)
	guestIpMap := make(map[string]string)
	ipsetMemberIpv6Map := make(map[string]string)
	for _, member := range eipIpset.Member {
		ipsetMemberMap[member] = member
	}
	if eipIpv6Ipset != nil {
		for _, member := range eipIpv6Ipset.Member {
			ipsetMemberIpv6Map[member] = member
		}
	}

	var toAddMemeber []string
	var toDelMemeber []string
	var toAddIpv6Memeber []string
	var toDelIpv6Memeber []string
	for _, eip := range eipMap {
		if eip.IpVersion == IP_VERSION_6 {
			if _, ok := ipsetMemberIpv6Map[eip.GuestIp]; !ok {
				toAddIpv6Memeber = append(toAddIpv6Memeber, eip.GuestIp)
			}
		} else {
			if _, ok := ipsetMemberMap[eip.GuestIp]; !ok {
				toAddMemeber = append(toAddMemeber, eip.GuestIp)
			}
		}
		guestIpMap[eip.GuestIp] = eip.GuestIp
		log.Debugf("add member %s guestIpMap", eip.GuestIp)
	}
	for _, member := range eipIpset.Member {
		if _, ok := guestIpMap[member]; !ok {
			toDelMemeber = append(toDelMemeber, member)
		}
	}
	if eipIpv6Ipset != nil {
		for _, member := range eipIpv6Ipset.Member {
			if _, ok := guestIpMap[member]; !ok {
				toDelIpv6Memeber = append(toDelIpv6Memeber, member)
			}
		}
	}

	if len(toAddMemeber) != 0 {
		if err := eipIpset.AddMember(toAddMemeber); err != nil {
			log.Debugf("add member %s to eip ipset failed %v", toAddMemeber, err)
			return err
		}
	}

	if len(toAddIpv6Memeber) != 0 {
		if err := eipIpv6Ipset.AddMember(toAddIpv6Memeber); err != nil {
			log.Debugf("add member %s to eip ipv6 ipset failed %v", toAddIpv6Memeber, err)
			return err
		}
	}

	if len(toDelMemeber) != 0 {
		if err := eipIpset.DeleteMember(toDelMemeber); err != nil {
			log.Debugf("remove member %s from eip ipset failed %v", toDelMemeber, err)
			return err
		}
	}

	if len(toDelIpv6Memeber) != 0 {
		if err := eipIpv6Ipset.DeleteMember(toDelIpv6Memeber); err != nil {
			log.Debugf("remove member %s from eip ipv6 ipset failed %v", toDelIpv6Memeber, err)
			return err
		}
	}

	filterTable := utils.NewIpTables(utils.FirewallTable)
	filterIpv6Table := utils.NewIpTablesByIpVersion(utils.FirewallTable, utils.IP_VERSION_6)
	natTable := utils.NewIpTables(utils.NatTable)
	natIpv6Table := utils.NewIpTablesByIpVersion(utils.NatTable, utils.IP_VERSION_6)

	filterTable.RemoveIpTableRuleByComments(utils.EipRuleComment)
	filterIpv6Table.RemoveIpTableRuleByComments(utils.EipRuleComment)
	natTable.RemoveIpTableRuleByComments(utils.EipRuleComment)
	natIpv6Table.RemoveIpTableRuleByComments(utils.EipRuleComment)

	var natRules []*utils.IpTableRule
	var natIpv6Rules []*utils.IpTableRule
	var filterRule []*utils.IpTableRule
	var filterIpv6Rule []*utils.IpTableRule

	for _, eip := range eipMap {
		/* nat rule */
		nicname, err := utils.GetNicNameByMac(eip.PublicMac)
		rule := utils.NewIpTableRule(utils.RULESET_DNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_DNAT).SetComment(utils.EipRuleComment)
		rule.SetCompareTarget(true)
		if eip.IpVersion == IP_VERSION_6 {
			rule.SetDstIp(eip.VipIp + "/128").SetDnatTargetIp(eip.GuestIp)
			natIpv6Rules = append(natIpv6Rules, rule)
		} else {
			rule.SetDstIp(eip.VipIp + "/32").SetDnatTargetIp(eip.GuestIp)
			natRules = append(natRules, rule)
		}

		rule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.EipRuleComment)
		rule.SetCompareTarget(true)
		if eip.IpVersion == IP_VERSION_6 {
			rule.SetOutNic(nicname).SetSrcIp(eip.GuestIp + "/128").SetSnatTargetIp(eip.VipIp)
			natIpv6Rules = append(natIpv6Rules, rule)
		} else {
			rule.SetOutNic(nicname).SetSrcIp(eip.GuestIp + "/32").SetSnatTargetIp(eip.VipIp)
			natRules = append(natRules, rule)
		}

		prinicname, err := utils.GetNicNameByMac(eip.PrivateMac)
		utils.PanicOnError(err)

		if eip.SnatInboundTraffic {
			gwip, err := utils.GetIpByNicName(prinicname)
			utils.PanicOnError(err)

			rule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
			rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.EipRuleComment)
			if eip.IpVersion == IP_VERSION_6 {
				rule.SetOutNic(prinicname).SetDstIp(eip.GuestIp + "/128").SetSnatTargetIp(gwip)
				natIpv6Rules = append(natIpv6Rules, rule)
			} else {
				rule.SetOutNic(prinicname).SetDstIp(eip.GuestIp + "/32").SetSnatTargetIp(gwip)
				natRules = append(natRules, rule)
			}
		}

		/* firewall rule */
		rule = utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_IN))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.EipRuleComment)
		if eip.IpVersion == IP_VERSION_6 {
			filterIpv6Table.AddChain(utils.GetRuleSetName(prinicname, utils.RULESET_IN))
			rule.SetSrcIpset(EIP_IPV6_IPSET_NAME).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
			filterIpv6Rule = append(filterIpv6Rule, rule)
		} else {
			rule.SetDstIpset(EIP_IPSET_NAME).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
			filterRule = append(filterRule, rule)
		}

		rule = utils.NewIpTableRule(utils.GetRuleSetName(prinicname, utils.RULESET_IN))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.EipRuleComment)
		if eip.IpVersion == IP_VERSION_6 {
			filterIpv6Table.AddChain(utils.GetRuleSetName(nicname, utils.RULESET_IN))
			rule.SetSrcIpset(EIP_IPV6_IPSET_NAME).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
			filterIpv6Rule = append(filterIpv6Rule, rule)
		} else {
			rule.SetSrcIpset(EIP_IPSET_NAME).SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
			filterRule = append(filterRule, rule)
		}
	}

	filterTable.AddIpTableRules(filterRule)
	err := filterTable.Apply()
	utils.PanicOnError(err)

	filterIpv6Table.AddIpTableRules(filterIpv6Rule)
	err = filterIpv6Table.Apply()
	utils.PanicOnError(err)

	natTable.AddIpTableRules(natRules)
	err = natTable.Apply()
	utils.PanicOnError(err)

	natIpv6Table.AddIpTableRules(natIpv6Rules)
	err = natIpv6Table.Apply()
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

	if err := checkEipIpTableRules(cmd.Eips); err != nil {
		return err
	}

	for _, eip := range cmd.Eips {
		//clean wrong conntrack entries
		t := utils.ConnectionTrackTuple{IsNat: false, IsDst: true, Ip: eip.VipIp, Protocol: "tcp", PortStart: 0, PortEnd: 0, State: "SYN_SENT"}
		t.CleanConnTrackConnection()
	}

	return nil
}

func EipEntryPoint() {
	eipMap = make(map[string]eipInfo, EipInfoMaxSize)
	eipIpset = nil
	eipIpv6Ipset = nil
	ipsets, _ := utils.GetCurrentIpSet()
	for _, ipset := range ipsets {
		if ipset.Name == EIP_IPSET_NAME {
			eipIpset = ipset
			break
		}
	}
	ipv6Ipsets, _ := utils.GetCurrentIpSet()
	for _, ipset := range ipv6Ipsets {
		if ipset.Name == EIP_IPV6_IPSET_NAME {
			eipIpv6Ipset = ipset
			break
		}
	}

	server.RegisterAsyncCommandHandler(VR_CREATE_EIP, server.VyosLock(createEipHandler))
	server.RegisterAsyncCommandHandler(VR_REMOVE_EIP, server.VyosLock(removeEipHandler))
	server.RegisterAsyncCommandHandler(VR_SYNC_EIP, server.VyosLock(syncEipHandler))
}
