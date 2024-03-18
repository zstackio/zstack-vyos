package plugin

import (
	"fmt"

	"zstack-vyos/utils"

	log "github.com/sirupsen/logrus"
)

func configureNicByLinux(nicList []utils.NicInfo) interface{} {
	var nicname string
	for _, nic := range nicList {
		err := utils.Retry(func() error {
			var e error
			nicname, e = utils.GetNicNameByMac(nic.Mac)
			if e != nil {
				return e
			} else {
				return nil
			}
		}, 5, 1)
		utils.PanicOnError(err)
		utils.SetNicOption(nicname)
		/* avoid both master and backup interface up when add nic */
		if !IsMaster() && !utils.IsSLB() { /* slb don't need set interface down */
			log.Debugf("set interface %s down", nicname)
			err := utils.IpLinkSetDown(nicname)
			utils.Assertf(err == nil, "IpLinkSetDown[%s] error: %+v", nicname, err)
		} else {
			log.Debugf("set interface %s up", nicname)
			err := utils.IpLinkSetUp(nicname)
			utils.Assertf(err == nil, "IpLinkSetUp[%s] error: %+v", nicname, err)
			checkNicIsUp(nicname, true)
		}

		if nic.Ip != "" {
			err := utils.Ip4AddrFlush(nicname)
			utils.Assertf(err == nil, "IpAddr4Flush[%s] error: %+v", nicname, err)
			cidr, err := utils.NetmaskToCIDR(nic.Netmask)
			utils.PanicOnError(err)
			ipString := fmt.Sprintf("%v/%v", nic.Ip, cidr)
			log.Debugf("nic [%s] add ipv4 address %s", nicname, ipString)
			err = utils.IpAddrAdd(nicname, ipString)
			utils.Assertf(err == nil, "IpAddrAdd[%s, %s] error: %+v", nicname, ipString, err)
		}
		if nic.Ip6 != "" {
			err := utils.Ip6AddrFlush(nicname)
			utils.Assertf(err == nil, "IpAddr6Flush[%s] error: %+v", nicname, err)
			ip6String := fmt.Sprintf("%s/%d", nic.Ip6, nic.PrefixLength)
			log.Debugf("nic [%s] add ipv6 address %s", nicname, ip6String)
			err = utils.IpAddrAdd(nicname, ip6String)
			utils.Assertf(err == nil, "IpAddrAdd[%s, %s] error: %+v", nicname, ip6String, err)
		}
		mtu := 1500
		if nic.Mtu != 0 {
			mtu = nic.Mtu
		}
		if err := utils.IpLinkSetMTU(nicname, mtu); err != nil {
			log.Debugf("IpLinkSetMTU[%s, %d] error: %+v", nicname, mtu, err)
		}

		if nic.L2Type != "" {
			err := utils.IpLinkSetAlias(nicname, utils.MakeIfaceAlias(&nic))
			utils.Assertf(err == nil, "IpLinkSetAlias[%s] error: %+v", nicname, err)
		}
	}

	return nil
}

func configureNicDefaultActionByLinux(cmd *configureNicCmd) interface{} {
	var nicname string
	for _, nic := range cmd.Nics {
		err := utils.Retry(func() error {
			var e error
			nicname, e = utils.GetNicNameByMac(nic.Mac)
			if e != nil {
				return e
			} else {
				return nil
			}
		}, 5, 1)
		utils.PanicOnError(err)

		err = utils.SetNicDefaultFirewallRule(nicname, nic.FirewallDefaultAction)
		utils.PanicOnError(err)
	}

	return nil
}

func changeDefaultNicByLinux(cmd *ChangeDefaultNicCmd) interface{} {
	pubNic, err := utils.GetNicNameByMac(cmd.NewNic.Mac)
	utils.PanicOnError(err)

	if cmd.NewNic.Gateway != "" {
		err := utils.Ip4RouteDelDefault(utils.RT_TABLES_MAIN)
		utils.Assertf(err == nil, "IpRoute4DelDefault[] error: %+v", err)
		routeEntry := utils.NewIpRoute().SetGW(cmd.NewNic.Gateway).SetDev(pubNic).SetProto(utils.RT_PROTOS_STATIC).SetTable(utils.RT_TABLES_MAIN)
		err = utils.IpRouteAdd(routeEntry)
		utils.Assertf(err == nil, "IpRouteAdd[%+v] error: %+v", routeEntry, err)
	}
	if cmd.NewNic.Gateway6 != "" {
		err := utils.Ip6RouteDelDefault(utils.RT_TABLES_MAIN)
		utils.Assertf(err == nil, "IpRoute6DelDefault[] error: %+v", err)
		routeEntry := utils.NewIpRoute().SetGW(cmd.NewNic.Gateway).SetDev(pubNic).SetProto(utils.RT_PROTOS_STATIC).SetTable(utils.RT_TABLES_MAIN)
		err = utils.IpRouteAdd(routeEntry)
		utils.Assertf(err == nil, "IpRouteAdd[%+v] error: %+v", routeEntry, err)
	}

	defaultNic := &utils.Nic{Name: pubNic, Gateway: cmd.NewNic.Gateway, Gateway6: cmd.NewNic.Gateway6, Mac: cmd.NewNic.Mac,
		Ip: cmd.NewNic.Ip, Ip6: cmd.NewNic.Ip6}
	if utils.IsHaEnabled() {
		utils.WriteDefaultHaScript(defaultNic)
	}

	return nil
}

func setVipByLinux(cmd *setVipCmd) interface{} {
	if cmd.SyncVip {
		for _, nicIp := range cmd.NicIps {
			nicname, err := utils.GetNicNameByMac(nicIp.OwnerEthernetMac)
			utils.PanicOnError(err)
			linuxNicIps, err := utils.IpAddrShow(nicname)
			utils.PanicOnError(err)
			cidr, err := utils.NetmaskToCIDR(nicIp.Netmask)
			utils.PanicOnError(err)
			addr := fmt.Sprintf("%v/%v", nicIp.Ip, cidr)

			if len(linuxNicIps) == 0 || linuxNicIps[0] != addr {
				/* nicIp is not the first ip, reconfigured linux nic */
				if len(linuxNicIps) > 0 {
					for _, linuxIp := range linuxNicIps {
						err := utils.IpAddrDel(nicname, linuxIp)
						utils.PanicOnError(err)
					}
					err := utils.IpAddrAdd(nicname, addr)
					utils.PanicOnError(err)
				}
			}
		}
	}

	if !utils.IsHaEnabled() {
		for _, vip := range cmd.Vips {
			nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
			utils.PanicOnError(err)
			addr, _ := vip.GetIpWithCidr()
			err = utils.IpAddrAdd(nicname, addr)
			utils.PanicOnError(err)
		}
	} else {
		for _, vip := range cmd.Vips {
			nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
			utils.PanicOnError(err)
			addr, _ := vip.GetIpWithCidr()

			/* vip on mgt nic will not configure in vyos config */
			if vip.Ip != "" && utils.IsInManagementCidr(vip.Ip) {
				if IsMaster() {
					err := utils.IpAddrAdd(nicname, addr)
					utils.PanicOnError(err)
				}
			} else {
				err := utils.IpAddrAdd(nicname, addr)
				utils.PanicOnError(err)
			}
		}
	}

	if utils.IsConfigTcForVipQos() {
		for _, vip := range cmd.Vips {
			publicInterface, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
			utils.PanicOnError(err)
			ip := vip.GetIpWithOutCidr()
			ingressrule := newQosRule(ip, 0, MAX_BINDWIDTH, vip.VipUuid)
			if biRule, ok := totalQosRules[publicInterface]; ok {
				if biRule[INGRESS].InterfaceQosRuleFind(ingressrule) == nil {
					addQosRule(publicInterface, INGRESS, ingressrule)
				}
			} else {
				addQosRule(publicInterface, INGRESS, ingressrule)
			}

			egressrule := newQosRule(ip, 0, MAX_BINDWIDTH, vip.VipUuid)
			if biRule, ok := totalQosRules[publicInterface]; ok {
				if biRule[EGRESS].InterfaceQosRuleFind(egressrule) == nil {
					addQosRule(publicInterface, EGRESS, egressrule)
				}
			} else {
				addQosRule(publicInterface, EGRESS, egressrule)
			}
		}
	}

	vyosVips := []nicVipPair{}
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)
		ip := vip.GetIpWithOutCidr()
		_, cidr := vip.GetIpWithCidr()
		if utils.IsIpv4Address(ip) {
			vyosVips = append(vyosVips, nicVipPair{NicName: nicname, Vip: ip, Prefix: cidr})
		} else {
			vyosVips = append(vyosVips, nicVipPair{NicName: nicname, Vip6: ip, Prefix: cidr})
		}
	}

	if utils.IsHaEnabled() {
		addHaNicVipPair(vyosVips, false)
	}

	/* this is for debug, will be deleted */
	bash := utils.Bash{
		Command: fmt.Sprintf("ip add"),
	}
	bash.Run()

	go sendGARP(cmd)

	return nil
}

func removeVipByLinux(cmd *removeVipCmd) interface{} {
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)
		addr, _ := vip.GetIpWithCidr()
		if err = utils.IpAddrDel(nicname, addr); err != nil {
			return fmt.Errorf("IpAddrDel[%s, %s] error: %v", nicname, addr, err)
		}
		deleteQosRulesOfVip(nicname, vip.Ip)
	}

	vyosVips := []nicVipPair{}
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)
		_, cidr := vip.GetIpWithCidr()
		ip := vip.GetIpWithOutCidr()

		vyosVips = append(vyosVips, nicVipPair{NicName: nicname, Vip: ip, Prefix: cidr})
	}
	removeHaNicVipPair(vyosVips)

	/* this is for debug, will be deleted */
	bash := utils.Bash{
		Command: fmt.Sprintf("ip add"),
	}
	bash.Run()

	return nil
}

func setZebraRoutes(infos []routeInfo) {
	var (
		newEntry  *utils.ZebraRoute
		newRoutes []*utils.ZebraRoute
		oldRoutes []*utils.ZebraRoute
		err       error
	)

	// 1. get old routes by load json
	if err = utils.JsonLoadConfig(utils.ZEBRA_JSON_FILE, &oldRoutes); err != nil {
		log.Debugf("load old zebra route error: %+v", err)
	}

	// 2. apply new entry by vtysh
	for _, r := range infos {
		if r.Target == "" {
			newEntry = utils.NewZebraRoute().SetDst(r.Destination).SetDistance(r.Distance).SetNextHop(utils.BLACKHOLE_ROUTE)
		} else {
			newEntry = utils.NewZebraRoute().SetDst(r.Destination).SetNextHop(r.Target).SetDistance(r.Distance)
		}

		if err = newEntry.Apply(); err != nil {
			log.Debugf("apply route[%+v] error: %+v", r, err)
			utils.PanicOnError(err)
		}

		newRoutes = append(newRoutes, newEntry)
	}

	// 3. delete old entry that is not in new routes
	for _, old := range oldRoutes {
		isDelete := true
		for _, new := range newRoutes {
			if *old == *new {
				isDelete = false
			}
		}

		if isDelete {
			if err = old.SetDelete().Apply(); err != nil {
				log.Debugf("delete old route entry[] error: %+v", old)
			}
		}
	}

	// 4. store new routes
	if err = utils.JsonStoreConfig(utils.ZEBRA_JSON_FILE, newRoutes); err != nil {
		log.Debugf("load old zebra route error: %+v", err)
	}
}

func parseOspfToVtyshCmd(cmd *setOspfCmd) (*utils.VtyshOspfCmd, error) {
	var (
		v       *utils.VtyshOspfCmd
		nicName string
		err     error
	)

	v = utils.NewVtyshOspfCmd().SetRouteId(cmd.RouterId)
	for _, area := range cmd.AreaInfos {
		v.SetArea(area.AreaId, string(area.AreaType), string(area.AuthType))
	}
	for _, net := range cmd.NetworkInfos {
		v.SetNetwork(net.Network, net.AreaId)
		if nicName, err = utils.GetNicNameByMac(net.NicMac); err != nil {
			return nil, err
		}
		for _, area := range cmd.AreaInfos {
			if area.AreaId == net.AreaId {
				v.SetInterface(nicName, string(area.AuthType), area.AuthParam)
			}
		}
	}

	return v, nil
}

func configureOspfByVtysh(cmd *setOspfCmd) {
	var (
		oldCmd *utils.VtyshOspfCmd
		newCmd *utils.VtyshOspfCmd
		tmp    *utils.VtyshOspfCmd
		err    error
	)
	// 1. get old ospf cmd
	oldCmd = utils.NewVtyshOspfCmd().SetDelete()
	utils.JsonLoadConfig(utils.OSPF_JSON_FILE, &oldCmd)

	// 2. get new ospf cmd
	newCmd, err = parseOspfToVtyshCmd(cmd)
	utils.PanicOnError(err)

	// 3. delete the same cmd in new and old
	for k, new := range newCmd.NetworkCmd {
		if old, ok := oldCmd.NetworkCmd[k]; ok && new == old {
			newCmd.DeleteNetwork(k)
			oldCmd.DeleteNetwork(k)
		}
	}
	for k, new := range newCmd.AreaCmd {
		if old, ok := oldCmd.AreaCmd[k]; ok && new == old {
			newCmd.DeleteArea(k)
			oldCmd.DeleteArea(k)
		}
	}
	for k, new := range newCmd.IfaceCmd {
		if old, ok := oldCmd.IfaceCmd[k]; ok && new == old {
			newCmd.DeleteInterface(k)
			oldCmd.DeleteInterface(k)
		}
	}

	// 4. delete old cmd, and apply new cmd
	log.Debugf("vtysh-ospf: start delete ospf cmd[%+v]", oldCmd)
	err = oldCmd.Apply()
	utils.PanicOnError(err)
	log.Debugf("vtysh-ospf: start apply ospf cmd[%+v]", newCmd)
	err = newCmd.Apply()
	utils.PanicOnError(err)

	// 5. store new cmd
	tmp, err = parseOspfToVtyshCmd(cmd)
	utils.PanicOnError(err)
	err = utils.JsonStoreConfig(utils.OSPF_JSON_FILE, tmp)
	utils.PanicOnError(err)
}
