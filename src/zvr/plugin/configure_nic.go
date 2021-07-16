package plugin

import (
	"zvr/server"
	"zvr/utils"
	"fmt"
	"github.com/pkg/errors"
	"strings"
	log "github.com/Sirupsen/logrus"
)

const (
	VR_CONFIGURE_NIC = "/configurenic"
	VR_CONFIGURE_NIC_FIREWALL_DEFAULT_ACTION_PATH = "/configurenicdefaultaction"
	VR_REMOVE_NIC_PATH = "/removenic"
	VR_CHANGE_DEFAULT_NIC_PATH = "/changeDefaultNic"
	ROUTE_STATE_NEW_ENABLE_FIREWALL_RULE_NUMBER = 9999
	RA_MAX_INTERVAL = 60
	RA_MIN_INTERVAL = 15
)

type nicInfo struct {
	Ip                    string `json:"ip"`
	Netmask               string `json:"netmask"`
	Gateway               string `json:"gateway"`
	Mac                   string `json:"Mac"`
	Category              string `json:"category"`
	L2Type                string `json:"l2type"`
	PhysicalInterface     string `json:"physicalInterface"`
	Vni                   int    `json:"vni"`
	FirewallDefaultAction string `json:"firewallDefaultAction"`
	Mtu                   int    `json:"mtu"`
	Ip6                   string `json:"Ip6"`
	PrefixLength          int    `json:"PrefixLength"`
	Gateway6              string `json:"Gateway6"`
	AddressMode           string `json:"AddressMode"`
}

type addNicCallback interface {
	AddNic(nic string) error
}

type removeNicCallback interface {
	RemoveNic(nic string) error
}

var addNicCallbacks []addNicCallback
var removeNicCallbacks []removeNicCallback
var nicsMap map[string]utils.Nic

func init() {
	addNicCallbacks = make([]addNicCallback, 0)
	removeNicCallbacks = make([]removeNicCallback, 0)
	nicsMap = make(map[string]utils.Nic, 32)
}

func getNicIp(nicName string) string {
	if nic, ok := nicsMap[nicName]; !ok {
		return ""
	} else {
		return nic.Ip
	}
}

func RegisterAddNicCallback(cb addNicCallback)  {
	addNicCallbacks = append(addNicCallbacks, cb)
}

func RegisterRemoveNicCallback(cb removeNicCallback)  {
	removeNicCallbacks = append(removeNicCallbacks, cb)
}

type configureNicCmd struct {
	Nics []nicInfo `json:"nics"`
}

type ChangeDefaultNicCmd struct {
	NewNic nicInfo `json:"newNic"`
	Snats []snatInfo `json:"snats"`
}

func makeNicFirewallDescription(nicname, ip string) string {
	return fmt.Sprintf("nic-%s-secondary-ip-%s", nicname, ip)
}

func addSecondaryIpFirewall(nicname, ip string,  tree *server.VyosConfigTree)  {
	if (utils.IsSkipVyosIptables()) {
		rule := utils.NewIptablesRule("", "", ip, 0, 0, []string{utils.RELATED, utils.ESTABLISHED}, utils.ACCEPT, utils.VRRPComment)
		utils.InsertFireWallRule(nicname, rule, utils.LOCAL)
		rule = utils.NewIptablesRule("icmp", "", ip, 0, 0, nil, utils.ACCEPT, utils.VRRPComment)
		utils.InsertFireWallRule(nicname, rule, utils.LOCAL)
	} else {
		des := makeNicFirewallDescription(nicname, ip)
		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("description %s", des),
				"action accept",
				"state established enable",
				"state related enable",
				fmt.Sprintf("destination address %s", ip),
			)

			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("description %s", des),
				"action accept",
				"protocol icmp",
				fmt.Sprintf("destination address %s", ip),
			)
		}
		tree.AttachFirewallToInterface(nicname, "local")
	}

}

func configureLBFirewallRule(tree *server.VyosConfigTree, dev string) (err error) {
	/*get all the rules created by lb from an private nic first;
	config these rules on dev second*/

	err = nil
	des := "LB-*-*"
	var sourceNic string

	priNics := utils.GetPrivteInterface()
	for _, priNic := range priNics {
		if priNic != dev && tree.FindFirewallRuleByDescriptionRegex(priNic, "local", des, utils.StringRegCompareFn) != nil {
			sourceNic = priNic
			break
		}
	}

	log.Debug(sourceNic)

	if utils.IsSkipVyosIptables() {
		//removeDnsFirewallRules(priNic)
	} else {
		if rs := tree.FindFirewallRulesByDescriptionRegex(sourceNic, "local", des, utils.StringRegCompareFn); rs != nil {
			for _, r := range rs {
				prefix := r.String()
				rule := make([]string, 0)
				for _, d := range r.FullString() {
					rule = append(rule, strings.Replace(d, prefix, "", -1))
				}
				log.Debug(rule)
				log.Debug(r.String())
				tree.SetFirewallOnInterface(dev, "local", rule...)
			}
		}
	}

	return
}

func configureNic(ctx *server.CommandContext) interface{} {
	cmd := &configureNicCmd{}
	ctx.GetCommand(cmd)

	tree := server.NewParserFromShowConfiguration().Tree
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
		}, 5, 1); utils.PanicOnError(err)
		err = utils.Retry(func() error {
			bash := utils.Bash{
				Command: fmt.Sprintf("sudo /sbin/ethtool %s", nicname),
			}
			_, _, _, e := bash.RunWithReturn()
			return e
		}, 30, 1); utils.PanicOnError(err)
		if nic.Ip != "" {
			cidr, err := utils.NetmaskToCIDR(nic.Netmask)
			utils.PanicOnError(err)
			addr := fmt.Sprintf("%v/%v", nic.Ip, cidr)
			tree.Setf("interfaces ethernet %s address %v", nicname, addr)
		}
		if nic.Ip6 != "" {
			tree.SetfWithoutCheckExisting("interfaces ethernet %s address %s", nicname, fmt.Sprintf("%s/%d", nic.Ip6, nic.PrefixLength))
		}

		tree.SetfWithoutCheckExisting("interfaces ethernet %s duplex auto", nicname)
		tree.SetNicSmpAffinity(nicname, "auto")
		tree.SetfWithoutCheckExisting("interfaces ethernet %s speed auto", nicname)
		mtu := 1500
		if nic.Mtu != 0 {
			mtu = nic.Mtu
		}
		tree.SetNicMtu(nicname, mtu)

		if nic.Ip6 != "" && nic.Category == "Private"{
			switch nic.AddressMode {
			case "Stateful-DHCP":
				tree.Setf("interfaces ethernet %s ipv6 router-advert managed-flag true", nicname)
				tree.Setf("interfaces ethernet %s ipv6 router-advert other-config-flag true", nicname)
				tree.Setf("interfaces ethernet %s ipv6 router-advert prefix %s/%d autonomous-flag false", nicname, nic.Ip6, nic.PrefixLength)
			case "Stateless-DHCP":
				tree.Setf("interfaces ethernet %s ipv6 router-advert managed-flag false", nicname)
				tree.Setf("interfaces ethernet %s ipv6 router-advert other-config-flag true", nicname)
				tree.Setf("interfaces ethernet %s ipv6 router-advert prefix %s/%d autonomous-flag true", nicname, nic.Ip6, nic.PrefixLength)
			case "SLAAC":
				tree.Setf("interfaces ethernet %s ipv6 router-advert managed-flag false", nicname)
				tree.Setf("interfaces ethernet %s ipv6 router-advert other-config-flag false", nicname)
				tree.Setf("interfaces ethernet %s ipv6 router-advert prefix %s/%d autonomous-flag true", nicname, nic.Ip6, nic.PrefixLength)
			}
			tree.Setf("interfaces ethernet %s ipv6 router-advert prefix %s/%d on-link-flag true", nicname, nic.Ip6, nic.PrefixLength)
			tree.Setf("interfaces ethernet %s ipv6 router-advert max-interval %d", nicname, RA_MAX_INTERVAL)
			tree.Setf("interfaces ethernet %s ipv6 router-advert min-interval %d", nicname, RA_MIN_INTERVAL)
			tree.Setf("interfaces ethernet %s ipv6 router-advert send-advert true", nicname)
		}

		if utils.IsSkipVyosIptables() {
			if nic.Category == "Private" {
				utils.InitNicFirewall(nicname, nic.Ip, false, utils.REJECT)
			} else {
				utils.InitNicFirewall(nicname, nic.Ip, true, utils.REJECT)
			}
		} else {
			tree.SetFirewallOnInterface(nicname, "local",
				"action accept",
				"state established enable",
				"state related enable",
				fmt.Sprintf("destination address %v", nic.Ip),
			)
			tree.SetFirewallOnInterface(nicname, "local",
				"action accept",
				"protocol icmp",
				fmt.Sprintf("destination address %v", nic.Ip),
			)

			if nic.Category == "Private" {
				tree.SetZStackFirewallRuleOnInterface(nicname, "behind","in",
					"action accept",
					"state established enable",
					"state related enable",
					"state invalid enable",
					"state new enable",
				)
			} else {
				tree.SetZStackFirewallRuleOnInterface(nicname, "behind","in",
					"action accept",
					"state established enable",
					"state related enable",
				)

				tree.SetFirewallWithRuleNumber(nicname, "in", ROUTE_STATE_NEW_ENABLE_FIREWALL_RULE_NUMBER,
					"action accept",
					"state new enable",
				)
			}

			tree.SetZStackFirewallRuleOnInterface(nicname, "behind","in",
				"action accept",
				"protocol icmp",
			)

			// only allow ssh traffic on eth0, disable on others
			if nicname == "eth0" {
				tree.SetFirewallOnInterface(nicname, "local",
					fmt.Sprintf("destination port %v", int(utils.GetSshPortFromBootInfo())),
					fmt.Sprintf("destination address %v", nic.Ip),
					"protocol tcp",
					"action accept",
				)
			} else {
				tree.SetFirewallOnInterface(nicname, "local",
					fmt.Sprintf("destination port %v", int(utils.GetSshPortFromBootInfo())),
					fmt.Sprintf("destination address %v", nic.Ip),
					"protocol tcp",
					"action reject",
				)
			}

			tree.SetFirewallDefaultAction(nicname, "local", "reject")
			tree.SetFirewallDefaultAction(nicname, "in", "reject")

			tree.AttachFirewallToInterface(nicname, "local")
			tree.AttachFirewallToInterface(nicname, "in")
		}

		if nic.L2Type != "" {
			tree.Setf("interfaces ethernet %s description '%s'", nicname, makeAlias(nic))
		}

		if nic.Category == "Private" {
			log.Debug("start configure LB firewall rule")
			configureLBFirewallRule(tree, nicname)
		}

		if !IsMaster() {
			tree.Setf("interfaces ethernet %s disable", nicname)
		}
	}

	tree.Apply(false)

	if IsMaster() {
		if utils.Vyos_version == utils.VYOS_1_2 {
			bash := utils.Bash {
				Command: fmt.Sprintf("ip link set up dev %s", nicname),
				Sudo: true,
			}
			bash.Run()
		}
		
		checkNicIsUp(nicname, true)
	}

	generateNotityScripts()
	for _, nic := range cmd.Nics {
		/* TODO: add ipv6 dad */
		if nic.Ip == "" {
			continue
		}

		nicname, err := utils.GetNicNameByMac(nic.Mac)
		if err != nil {
			continue
		}

		if (!utils.IsHaEnabled()) {
			if nic.Ip != "" && utils.CheckIpDuplicate(nicname, nic.Ip) == true {
				utils.PanicOnError(errors.Errorf("duplicate ip %s in nic %s", nic.Ip, nic.Mac))
			}
		}

		for _, cb := range addNicCallbacks {
			cb.AddNic(nicname)
		}
		
		nicsMap[nicname] = utils.Nic{Name:nicname, Mac: nic.Mac, Ip:nic.Ip, Ip6: nic.Ip6,
			Gateway:nic.Gateway, Gateway6:nic.Gateway6}
	}

	/* this is for debug, will be deleted */
	bash := utils.Bash{
		Command: fmt.Sprintf("ip add"),
	}
	bash.Run()

	return nil
}

func checkNicIsUp(nicname string, panicIfDown bool) error {
	var retryTimes uint = 10
	var retryInterval uint = 1

	bash := utils.Bash{
		Command:fmt.Sprintf("sudo ip link show dev %s up", nicname),
	}
	err := utils.Retry(func() error {
		_, o, _, _ := bash.RunWithReturn()
		if o == "" {
			return errors.New(fmt.Sprintf("nic %s is down", nicname))
		} else {
			return nil
		}
	}, retryTimes, retryInterval)
	error := errors.New(fmt.Sprintf("nic %s still down after %d secondes", nicname, retryTimes * retryInterval))

	if err != nil && panicIfDown == true {
		utils.PanicOnError(error)
	} else if err != nil {
		return error
	}

	return nil
}

func removeNic(ctx *server.CommandContext) interface{} {
	cmd := &configureNicCmd{}
	ctx.GetCommand(cmd)

	tree := server.NewParserFromShowConfiguration().Tree
	for _, nic := range cmd.Nics {
		var nicname string
		err := utils.Retry(func() error {
			var e error
			nicname, e = utils.GetNicNameByMac(nic.Mac)
			if e != nil {
				return e
			} else {
				return nil
			}
		}, 5, 1); utils.PanicOnError(err)
		tree.Deletef("interfaces ethernet %s", nicname)
		if utils.IsSkipVyosIptables() {
			utils.DestroyNicFirewall(nicname)
		} else {
			tree.Deletef("firewall name %s.in", nicname)
			tree.Deletef("firewall name %s.local", nicname)
		}
	}
	tree.Apply(false)

	generateNotityScripts()

	for _, nic := range cmd.Nics {
		nicName, _:= utils.GetNicNameByMac(nic.Mac)
		for _, cb := range removeNicCallbacks {
			cb.RemoveNic(nicName)
		}
		
		delete(nicsMap, nicName)
	}

	/* this is for debug, will be deleted */
	bash := utils.Bash{
		Command: fmt.Sprintf("ip add"),
	}
	bash.Run()

	return nil
}

func configureNicFirewallDefaultAction(ctx *server.CommandContext) interface{} {
	cmd := &configureNicCmd{}
	ctx.GetCommand(cmd)

	tree := server.NewParserFromShowConfiguration().Tree
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
		}, 5, 1); utils.PanicOnError(err)

		if utils.IsSkipVyosIptables() {
			utils.SetDefaultRule(nicname, nic.FirewallDefaultAction)
		} else {
			if (strings.Compare(nic.FirewallDefaultAction, "reject") == 0) {
				tree.SetFirewallDefaultAction(nicname, "local", "reject")
				tree.SetFirewallDefaultAction(nicname, "in", "reject")
			} else {
				tree.SetFirewallDefaultAction(nicname, "local", "accept")
				tree.SetFirewallDefaultAction(nicname, "in", "accept")
			}
		}
	}

	tree.Apply(false)
	return nil
}

func changeDefaultNic(ctx *server.CommandContext) interface{} {
	cmd := &ChangeDefaultNicCmd{}
	ctx.GetCommand(cmd)

	tree := server.NewParserFromShowConfiguration().Tree
	/* change default gateway */
	pubNic, err := utils.GetNicNameByMac(cmd.NewNic.Mac); utils.PanicOnError(err)
	tree.Deletef("protocols static route 0.0.0.0/0")
	tree.Deletef("protocols static route6 ::/0")
	if cmd.NewNic.Gateway != "" {
		tree.Setf("protocols static route 0.0.0.0/0 next-hop %v", cmd.NewNic.Gateway)
	}
	if cmd.NewNic.Gateway6 != "" {
		tree.Setf("protocols static route6 ::/0 next-hop %v", cmd.NewNic.Gateway6)
	}

	if utils.IsSkipVyosIptables() {
		/* delete all snat rules */
		utils.DeleteSNatRuleByComment(utils.SNATComment)

		for _, s := range cmd.Snats {
			outNic, err := utils.GetNicNameByMac(s.PublicNicMac); utils.PanicOnError(err)
			inNic, err := utils.GetNicNameByMac(s.PrivateNicMac); utils.PanicOnError(err)
			address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask); utils.PanicOnError(err)

			setSnatRule(outNic, inNic, address, s.PublicIp)
		}
	} else {
		for _, s := range cmd.Snats {
			outNic, err := utils.GetNicNameByMac(s.PublicNicMac); utils.PanicOnError(err)
			inNic, err := utils.GetNicNameByMac(s.PrivateNicMac); utils.PanicOnError(err)
			nicNumber, err := utils.GetNicNumber(inNic); utils.PanicOnError(err)
			address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask); utils.PanicOnError(err)

			pubNicRuleNo, priNicRuleNo := getNicSNATRuleNumber(nicNumber)
			if rs := tree.Getf("nat source rule %v", pubNicRuleNo); rs != nil {
				rs.Delete()
			}

			if rs := tree.Getf("nat source rule %v", priNicRuleNo); rs != nil {
				rs.Delete()
			}

			tree.SetSnatWithRuleNumber(pubNicRuleNo,
				fmt.Sprintf("outbound-interface %s", outNic),
				fmt.Sprintf("source address %s", address),
				"destination address !224.0.0.0/8",
				fmt.Sprintf("translation address %s", s.PublicIp),
			)

			tree.SetSnatWithRuleNumber(priNicRuleNo,
				fmt.Sprintf("outbound-interface %s", inNic),
				fmt.Sprintf("source address %v", address),
				"destination address !224.0.0.0/8",
				fmt.Sprintf("translation address %s", s.PublicIp),
			)
		}
	}

	tree.Apply(false)

	/* delete snat connection on old gateway */
	if len(cmd.Snats) > 0 {
		t := utils.ConnectionTrackTuple{IsNat:true, IsDst: true, Ip: cmd.Snats[0].PublicIp, Protocol: "",
			PortStart: 0, PortEnd: 0}
		t.CleanConnTrackConnection()
	}

	defaultNic := &utils.Nic{Name: pubNic, Gateway: cmd.NewNic.Gateway, Gateway6:cmd.NewNic.Gateway6, Mac:cmd.NewNic.Mac,
		Ip: cmd.NewNic.Ip, Ip6: cmd.NewNic.Ip6}
	if utils.IsHaEnabled() {
		utils.WriteDefaultHaScript(defaultNic)
	}

	return err
}

func makeAlias(nic nicInfo) string {
	result := ""
	if nic.L2Type != "" {
		result += fmt.Sprintf("l2type:%s;", nic.L2Type)
	}
	if nic.Category != "" {
		result += fmt.Sprintf("category:%s;", nic.Category)
	}
	if nic.PhysicalInterface != "" {
		result += fmt.Sprintf("physicalInterface:%s;", nic.PhysicalInterface)
	}
	result += fmt.Sprintf("vni:%d;", nic.Vni)
	return result
}

func ConfigureNicEntryPoint()  {
	nicIps := utils.GetBootStrapNicInfo()
	for _, nic := range nicIps{
		nicsMap[nic.Name] = nic
	}
	
	server.RegisterAsyncCommandHandler(VR_CONFIGURE_NIC, server.VyosLock(configureNic))
	server.RegisterAsyncCommandHandler(VR_REMOVE_NIC_PATH, server.VyosLock(removeNic))
	server.RegisterAsyncCommandHandler(VR_CONFIGURE_NIC_FIREWALL_DEFAULT_ACTION_PATH, server.VyosLock(configureNicFirewallDefaultAction))
	server.RegisterAsyncCommandHandler(VR_CHANGE_DEFAULT_NIC_PATH, server.VyosLock(changeDefaultNic))
}