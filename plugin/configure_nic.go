package plugin

import (
	"fmt"
	"strings"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	VR_CONFIGURE_NIC                              = "/configurenic"
	VR_CONFIGURE_NIC_FIREWALL_DEFAULT_ACTION_PATH = "/configurenicdefaultaction"
	VR_REMOVE_NIC_PATH                            = "/removenic"
	VR_CHANGE_DEFAULT_NIC_PATH                    = "/changeDefaultNic"
	RA_MAX_INTERVAL                               = 60
	RA_MIN_INTERVAL                               = 15
)

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

func RegisterAddNicCallback(cb addNicCallback) {
	addNicCallbacks = append(addNicCallbacks, cb)
}

func RegisterRemoveNicCallback(cb removeNicCallback) {
	removeNicCallbacks = append(removeNicCallbacks, cb)
}

type configureNicCmd struct {
	Nics []utils.NicInfo `json:"nics"`
}

type ChangeDefaultNicCmd struct {
	NewNic utils.NicInfo `json:"newNic"`
	Snats  []snatInfo    `json:"snats"`
}

func makeNicFirewallDescription(nicname, ip string) string {
	return fmt.Sprintf("nic-%s-secondary-ip-%s", nicname, ip)
}

func addSecondaryIpFirewall(nicname, ip string, tree *server.VyosConfigTree) {
	if utils.IsSkipVyosIptables() {
		/* todo: we need ip6tables */
		if !utils.IsIpv4Address(ip) {
			return
		}

		rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
		rule.SetComment(utils.SystemTopRule).SetAction(utils.IPTABLES_ACTION_ACCEPT)
		rule.SetDstIp(ip + "/32").SetState([]string{utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})

		rule1 := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
		rule1.SetComment(utils.SystemTopRule).SetAction(utils.IPTABLES_ACTION_ACCEPT)
		rule1.SetDstIp(ip + "/32").SetProto(utils.IPTABLES_PROTO_ICMP)

		table := utils.NewIpTables(utils.FirewallTable)
		table.AddIpTableRules([]*utils.IpTableRule{rule, rule1})
		err := table.Apply()
		if err != nil {
			log.Debugf("add secondary IP firewall failed %s", err)
		}
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

func configureLBFirewallRuleByVyos(tree *server.VyosConfigTree, dev string) (err error) {
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

	if utils.IsSkipVyosIptables() {
		/*find := false
		for _, priNic := range priNics {
			if ruleString, err := utils.ListRule(utils.FirewallTable, priNic + utils.RULESET_LOCAL.String()) ; err == nil && priNic != dev {
				for _, rule := range ruleString{
					if strings.Contains(rule, utils.LbRuleComment) {
						find = true
						sourceNic = priNic
						break
						}
				}
			}
			if find {
				break
			}
		}


		ruleString, err := utils.ListRule(utils.FirewallTable, sourceNic+utils.RULESET_LOCAL.String())
		if  err != nil{
				log.Debugf("failed to get rule of table %s chain %s, because %v",utils.FirewallTable, sourceNic+utils.RULESET_LOCAL.String(), err)
				return err
		}
		cmds := make([]string, 0)
		for _, r := range ruleString {
				if strings.Contains(r, utils.LbRuleComment) {
						r = strings.Replace(r, sourceNic + utils.RULESET_LOCAL.String(), dev + utils.RULESET_LOCAL.String(), 1)
						cmds = append(cmds, fmt.Sprintf("iptables %s", r))
				}
		}
		b := utils.Bash{
				Command: strings.Join(cmds, "\n"),
					Sudo: true,
		}
		_, _, _, err = b.RunWithReturn()
		if err != nil {
				return err
		}*/
		//removeDnsFirewallRules(priNic)
	} else {

	}

	return
}

func configureLBFirewallRuleByIpTables(dev string) error {
	sourceNic := ""
	priNics := utils.GetPrivteInterface()
	for _, priNic := range priNics {
		if priNic != dev {
			sourceNic = priNic
			break
		}
	}

	if sourceNic == "" {
		log.Debugf("this is the first private nic %s", dev)
		return nil
	}

	table := utils.NewIpTables(utils.FirewallTable)
	rules := table.Found(utils.GetRuleSetName(sourceNic, utils.RULESET_LOCAL), utils.LbRuleComment)
	if len(rules) == 0 {
		log.Debugf("there is no private loadBalancer configure for nic: %s", sourceNic)
		return nil
	}

	newChainName := utils.GetRuleSetName(dev, utils.RULESET_LOCAL)
	for _, r := range rules {
		r.SetChainName(newChainName)
	}
	log.Debugf("add private lb rules for nic: %s, rules %+v", dev, rules)
	table.AddIpTableRules(rules)

	return table.Apply()
}

func configureNicHandler(ctx *server.CommandContext) interface{} {
	cmd := &configureNicCmd{}
	ctx.GetCommand(cmd)

	return configureNic(cmd)
}

func configureNicFirewall(nics []utils.NicInfo) {
	if utils.IsSkipVyosIptables() {
		for _, nic := range nics {
			nicname, _ := utils.GetNicNameByMac(nic.Mac)

			if nic.Category == "Private" {
				err := utils.InitNicFirewall(nicname, nic.Ip, false, utils.IPTABLES_ACTION_REJECT)
				utils.PanicOnError(err)
			} else {
				err := utils.InitNicFirewall(nicname, nic.Ip, true, utils.IPTABLES_ACTION_REJECT)
				utils.PanicOnError(err)
			}

			if nic.Category == "Private" {
				log.Debug("start configure LB firewall rule for new added nic")
				configureLBFirewallRuleByIpTables(nicname)
			}
		}
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		for _, nic := range nics {
			nicname, _ := utils.GetNicNameByMac(nic.Mac)
			tree.SetFirewallDefaultAction(nicname, "local", "reject")
			tree.SetFirewallDefaultAction(nicname, "in", "reject")
		}
		tree.Apply(false)

		tree = server.NewParserFromShowConfiguration().Tree
		for _, nic := range nics {
			nicname, _ := utils.GetNicNameByMac(nic.Mac)
			tree.AttachFirewallToInterface(nicname, "local")
			tree.AttachFirewallToInterface(nicname, "in")
		}
		tree.Apply(false)

		tree = server.NewParserFromShowConfiguration().Tree
		for _, nic := range nics {
			nicname, _ := utils.GetNicNameByMac(nic.Mac)
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

			tree.SetZStackFirewallRuleOnInterface(nicname, "behind", "in",
				"action accept",
				"state established enable",
				"state related enable",
			)

			tree.SetFirewallWithRuleNumber(nicname, "in", utils.IPTABLES_RULENUMBER_9999,
				"action accept",
				"state new enable",
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

			if nic.Category == "Private" {
				log.Debug("start configure LB firewall rule")
				configureLBFirewallRuleByVyos(tree, nicname)
			}
		}

		tree.Apply(false)
	}
}

func configureNicByVyos(nicList []utils.NicInfo) interface{} {
	var nicname string
	for _, nic := range nicList {
		tree := server.NewParserFromShowConfiguration().Tree
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
		if !IsMaster() {
			/* avoid both master and backup interface up when add nic */
			tree.Setf("interfaces ethernet %s disable", nicname)
			tree.Apply(false)
			tree = server.NewParserFromShowConfiguration().Tree
		}

		err = utils.Retry(func() error {
			bash := utils.Bash{
				Command: fmt.Sprintf("sudo /sbin/ethtool %s", nicname),
			}
			_, _, _, e := bash.RunWithReturn()
			return e
		}, 30, 1)
		utils.PanicOnError(err)
		if nic.Ip != "" {
			cidr, err := utils.NetmaskToCIDR(nic.Netmask)
			utils.PanicOnError(err)
			addr := fmt.Sprintf("%v/%v", nic.Ip, cidr)
			tree.Setf(fmt.Sprintf("interfaces ethernet %s address %v", nicname, addr))
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

		if nic.L2Type != "" {
			tree.Setf("interfaces ethernet %s description '%s'", nicname, makeAlias(nic))
		}

		if !IsMaster() && !utils.IsSLB() { /* slb don't need interface down */
			tree.Setf("interfaces ethernet %s disable", nicname)
		}
		tree.Apply(false)

		if IsMaster() {
			bash := utils.Bash{
				Command: fmt.Sprintf("ip link set up dev %s", nicname),
				Sudo:    true,
			}
			bash.Run()

			checkNicIsUp(nicname, true)
		}
	}

	return nil
}

func configureNic(cmd *configureNicCmd) interface{} {
	if !utils.IsEnableVyosCmd() {
		if err := configureNicByLinux(cmd.Nics); err != nil {
			return err
		}
	} else {
		if err := configureNicByVyos(cmd.Nics); err != nil {
			return err
		}
	}

	configureNicFirewall(cmd.Nics)

	radvdMap := make(utils.RadvdAttrsMap)
	for _, nic := range cmd.Nics {
		if nic.Ip6 != "" && nic.PrefixLength > 0 && nic.Category == "Private" {
			nicname, err := utils.GetNicNameByMac(nic.Mac)
			utils.PanicOnError(err)
			radvdAttr := utils.NewRadvdAttrs().SetNicName(nicname).SetIp6(nic.Ip6, nic.PrefixLength).SetMode(nic.AddressMode)
			radvdMap[nicname] = radvdAttr
		}
	}
	if err := radvdMap.ConfigService(); err != nil {
		return err
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

		if !utils.IsHaEnabled() {
			if nic.Ip != "" && utils.CheckIpDuplicate(nicname, nic.Ip) == true {
				utils.PanicOnError(errors.Errorf("duplicate ip %s in nic %s", nic.Ip, nic.Mac))
			}
		}

		for _, cb := range addNicCallbacks {
			cb.AddNic(nicname)
		}

		nicsMap[nicname] = utils.Nic{Name: nicname, Mac: nic.Mac, Ip: nic.Ip, Ip6: nic.Ip6,
			Gateway: nic.Gateway, Gateway6: nic.Gateway6}
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
		Command: fmt.Sprintf("sudo ip link show dev %s | grep 'state UP'", nicname),
	}
	err := utils.Retry(func() error {
		ret, o, _, err := bash.RunWithReturn()
		if ret != 0 || err != nil {
			return errors.New(fmt.Sprintf("nic %s is down, output: %s", nicname, o))
		} else {
			return nil
		}
	}, retryTimes, retryInterval)
	error := errors.New(fmt.Sprintf("nic %s still down after %d secondes", nicname, retryTimes*retryInterval))

	if err != nil && panicIfDown == true {
		utils.PanicOnError(error)
	} else if err != nil {
		return error
	}

	return nil
}

func removeNicHandler(ctx *server.CommandContext) interface{} {
	cmd := &configureNicCmd{}
	ctx.GetCommand(cmd)

	return removeNic(cmd)
}

func removeNic(cmd *configureNicCmd) interface{} {
	if utils.IsEnableVyosCmd() {
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
			}, 5, 1)
			utils.PanicOnError(err)
			tree.Deletef("interfaces ethernet %s", nicname)
			if utils.IsSkipVyosIptables() {
				err := utils.DestroyNicFirewall(nicname)
				utils.PanicOnError(err)
			} else {
				tree.Deletef("firewall name %s.in", nicname)
				tree.Deletef("firewall name %s.local", nicname)
			}
		}
		tree.Apply(false)
	} else {
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
			}, 5, 1)
			utils.PanicOnError(err)
			err = utils.DestroyNicFirewall(nicname)
			utils.PanicOnError(err)
			err = utils.IpAddrFlush(nicname)
			utils.PanicOnError(err)
		}
	}

	radvdMap := make(utils.RadvdAttrsMap)
	for _, nic := range cmd.Nics {
		nicname, err := utils.GetNicNameByMac(nic.Mac)
		utils.PanicOnError(err)
		delRadvd := utils.NewRadvdAttrs().SetNicName(nicname).SetDelete()
		radvdMap[nicname] = delRadvd
	}
	if err := radvdMap.ConfigService(); err != nil {
		return err
	}

	generateNotityScripts()

	for _, nic := range cmd.Nics {
		nicName, _ := utils.GetNicNameByMac(nic.Mac)
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

	if !utils.IsEnableVyosCmd() {
		return configureNicDefaultActionByLinux(cmd)
	}
	return configureNicDefaultAction(cmd)
}

func configureNicDefaultAction(cmd *configureNicCmd) interface{} {
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
		}, 5, 1)
		utils.PanicOnError(err)

		if utils.IsSkipVyosIptables() {
			err := utils.SetNicDefaultFirewallRule(nicname, nic.FirewallDefaultAction)
			utils.PanicOnError(err)
		} else {
			if strings.Compare(strings.ToLower(nic.FirewallDefaultAction), "reject") == 0 {
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

func changeDefaultNicHandler(ctx *server.CommandContext) interface{} {
	cmd := &ChangeDefaultNicCmd{}
	ctx.GetCommand(cmd)

	if !utils.IsEnableVyosCmd() {
		return changeDefaultNicByLinux(cmd)
	}
	return changeDefaultNic(cmd)
}

func changeDefaultNic(cmd *ChangeDefaultNicCmd) interface{} {
	tree := server.NewParserFromShowConfiguration().Tree
	/* change default gateway */
	pubNic, err := utils.GetNicNameByMac(cmd.NewNic.Mac)
	utils.PanicOnError(err)
	tree.Deletef("protocols static route 0.0.0.0/0")
	tree.Deletef("protocols static route6 ::/0")
	tree.Deletef("system gateway-address")
	if cmd.NewNic.Gateway != "" {
		tree.Setf("protocols static route 0.0.0.0/0 next-hop %v", cmd.NewNic.Gateway)
	}
	if cmd.NewNic.Gateway6 != "" {
		tree.Setf("protocols static route6 ::/0 next-hop %v", cmd.NewNic.Gateway6)
	}

	tree.Apply(false)

	defaultNic := &utils.Nic{Name: pubNic, Gateway: cmd.NewNic.Gateway, Gateway6: cmd.NewNic.Gateway6, Mac: cmd.NewNic.Mac,
		Ip: cmd.NewNic.Ip, Ip6: cmd.NewNic.Ip6}
	if utils.IsHaEnabled() {
		utils.WriteDefaultHaScript(defaultNic)
	}

	return nil
}

func makeAlias(nic utils.NicInfo) string {
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

func ConfigureNicEntryPoint() {
	nicIps := utils.GetBootStrapNicInfo()
	for _, nic := range nicIps {
		nicsMap[nic.Name] = nic
		if utils.IsSLB() {
			/* fix http://jira.zstack.io/browse/ZSTAC-64193 */
			utils.IpLinkSetUp(nic.Name)
		}
	}

	server.RegisterAsyncCommandHandler(VR_CONFIGURE_NIC, server.VyosLock(configureNicHandler))
	server.RegisterAsyncCommandHandler(VR_REMOVE_NIC_PATH, server.VyosLock(removeNicHandler))
	server.RegisterAsyncCommandHandler(VR_CONFIGURE_NIC_FIREWALL_DEFAULT_ACTION_PATH, server.VyosLock(configureNicFirewallDefaultAction))
	server.RegisterAsyncCommandHandler(VR_CHANGE_DEFAULT_NIC_PATH, server.VyosLock(changeDefaultNicHandler))
}
