package plugin

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"strings"
	"zstack-vyos/server"
	"zstack-vyos/utils"
)

const (
	CREATE_PORT_FORWARDING_PATH = "/createportforwarding"
	REVOKE_PORT_FORWARDING_PATH = "/revokeportforwarding"
	SYNC_PORT_FORWARDING_PATH   = "/syncportforwarding"
	PortForwardingInfoMaxSize   = 512
)

type dnatInfo struct {
	Uuid               string `json:"uuid"`
	VipPortStart       int    `json:"vipPortStart"`
	VipPortEnd         int    `json:"vipPortEnd"`
	PrivatePortStart   int    `json:"privatePortStart"`
	PrivatePortEnd     int    `json:"privatePortEnd"`
	ProtocolType       string `json:"protocolType"`
	VipIp              string `json:"vipIp"`
	PublicMac          string `json:"publicMac"`
	PrivateIp          string `json:"privateIp"`
	PrivateMac         string `json:"privateMac"`
	AllowedCidr        string `json:"allowedCidr"`
	SnatInboundTraffic bool   `json:"snatInboundTraffic"`
}

type setDnatCmd struct {
	Rules []dnatInfo `json:"rules"`
}

type removeDnatCmd struct {
	Rules []dnatInfo `json:"rules"`
}

type syncDnatCmd struct {
	Rules []dnatInfo `json:"rules"`
}

var pfMap map[string]dnatInfo

func syncPortForwardingRules() error {
	table := utils.NewIpTables(utils.FirewallTable)
	natTable := utils.NewIpTables(utils.NatTable)

	var filterRules []*utils.IpTableRule
	var dnatRules []*utils.IpTableRule

	table.RemoveIpTableRuleByComments(utils.PortFordingRuleComment)
	natTable.RemoveIpTableRuleByComments(utils.PortFordingRuleComment)

	for _, r := range pfMap {
		pubNicName, err := utils.GetNicNameByMac(r.PublicMac)
		utils.PanicOnError(err)

		protocol := utils.IPTABLES_PROTO_TCP
		if strings.ToLower(r.ProtocolType) != utils.IPTABLES_PROTO_TCP {
			protocol = utils.IPTABLES_PROTO_UDP
		}
		var portRange string
		var natPortRange string
		if r.VipPortEnd != r.VipPortStart {
			portRange = fmt.Sprintf("%d:%d", r.PrivatePortStart, r.PrivatePortEnd)
			natPortRange = fmt.Sprintf("%d:%d", r.VipPortStart, r.VipPortEnd)
		} else {
			portRange = fmt.Sprintf("%d", r.PrivatePortStart)
			natPortRange = fmt.Sprintf("%d", r.VipPortStart)
		}

		if r.AllowedCidr != "" && r.AllowedCidr != "0.0.0.0/0" {
			rule := utils.NewIpTableRule(utils.GetRuleSetName(pubNicName, utils.RULESET_IN))
			rule.SetAction(utils.IPTABLES_ACTION_REJECT).SetRejectType(utils.REJECT_TYPE_ICMP_UNREACHABLE)
			rule.SetComment(utils.PortFordingRuleComment)
			rule.SetSrcIp(fmt.Sprintf("! %s", r.AllowedCidr)).SetDstIp(fmt.Sprintf("%s/32", r.PrivateIp))
			rule.SetProto(protocol).SetDstPort(portRange).SetState([]string{utils.IPTABLES_STATE_NEW})
			filterRules = append(filterRules, rule)
		}
		rule := utils.NewIpTableRule(utils.GetRuleSetName(pubNicName, utils.RULESET_IN))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN)
		rule.SetComment(utils.PortFordingRuleComment)
		rule.SetDstIp(fmt.Sprintf("%s/32", r.PrivateIp))
		rule.SetProto(protocol).SetDstPort(portRange).SetState([]string{utils.IPTABLES_STATE_NEW})
		filterRules = append(filterRules, rule)

		rule = utils.NewIpTableRule(utils.RULESET_DNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_DNAT)
		rule.SetComment(utils.PortFordingRuleComment)
		rule.SetDstIp(fmt.Sprintf("%s/32", r.VipIp))
		rule.SetProto(protocol).SetDstPort(natPortRange)
		rule.SetDnatTargetIp(r.PrivateIp).SetDnatTargetPort(strings.Replace(portRange, ":", "-", -1))
		dnatRules = append(dnatRules, rule)
	}

	table.AddIpTableRules(filterRules)
	if err := table.Apply(); err != nil {
		log.Warnf("sync portforwarding firewall table failed %s", err.Error())
		utils.PanicOnError(err)
		return err
	}

	natTable.AddIpTableRules(dnatRules)
	if err := natTable.Apply(); err != nil {
		log.Warnf("sync portforwarding nat table failed %s", err.Error())
		utils.PanicOnError(err)
		return err
	}

	return nil
}

func syncDnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &syncDnatCmd{}
	ctx.GetCommand(cmd)

	return syncDnat(cmd)
}

func syncDnat(cmd *syncDnatCmd) interface{} {
	pfMap = make(map[string]dnatInfo, PortForwardingInfoMaxSize)

	if utils.IsSkipVyosIptables() {
		for _, rule := range cmd.Rules {
			pfMap[rule.Uuid] = rule
		}
		err := syncPortForwardingRules()
		utils.PanicOnError(err)
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		dnatRegex := ".*(\\w.){3}\\w-\\w{1,}-\\w{1,}-(\\w{2}:){5}\\w{2}-\\w{1,}-\\w{1,}-\\w{1,}"

		// delete all portforwarding related rules
		for {
			if r := tree.FindDnatRuleDescriptionRegex(dnatRegex, utils.StringRegCompareFn); r != nil {
				r.Delete()
			} else {
				break
			}
		}

		if len(cmd.Rules) > 1 {
			pubNicName, err := utils.GetNicNameByMac(cmd.Rules[0].PublicMac)
			utils.PanicOnError(err)
			for {
				if r := tree.FindFirewallRuleByDescriptionRegex(
					pubNicName, "in", dnatRegex, utils.StringRegCompareFn); r != nil {
					r.Delete()
				} else {
					break
				}
			}
		}

		setRuleInTree(tree, cmd.Rules)
		tree.Apply(false)
	}
	return nil
}

func getRule(tree *server.VyosConfigTree, description string) *server.VyosConfigNode {
	rs := tree.Get("nat destination rule")
	if rs == nil {
		return nil
	}

	for _, r := range rs.Children() {
		if des := r.Get("description"); des != nil && des.Value() == description {
			return r
		}
	}

	return nil
}

func makeDnatDescription(r dnatInfo) string {
	return fmt.Sprintf("PF-%v-%v-%v-%v-%v-%v-%v", r.VipIp, r.VipPortStart, r.VipPortEnd, r.PrivateMac, r.PrivatePortStart, r.PrivatePortEnd, r.ProtocolType)
}

func makeAllowCidrRejectDescription(r dnatInfo) string {
	return fmt.Sprintf("PF-reject-%v-%v-%v-%v-%v-%v-%v", r.VipIp, r.VipPortStart, r.VipPortEnd, r.PrivateMac, r.PrivatePortStart, r.PrivatePortEnd, r.ProtocolType)
}

func makeOrphanDnatDescription(r dnatInfo) string {
	return fmt.Sprintf("%v-%v-%v-%v-%v-%v-%v", r.VipIp, r.VipPortStart, r.VipPortEnd, r.PrivateMac, r.PrivatePortStart, r.PrivatePortEnd, r.ProtocolType)
}

func setRuleInTree(tree *server.VyosConfigTree, rules []dnatInfo) {
	for _, r := range rules {
		des := makeDnatDescription(r)
		if currentRule := getRule(tree, makeOrphanDnatDescription(r)); currentRule != nil {
			log.Debugf("dnat rule %s exists orphan rule, skip it", des)
			continue
		}

		var sport string
		if r.VipPortStart == r.VipPortEnd {
			sport = fmt.Sprintf("%v", r.VipPortStart)
		} else {
			sport = fmt.Sprintf("%v-%v", r.VipPortStart, r.VipPortEnd)
		}
		var dport string
		if r.PrivatePortStart == r.PrivatePortEnd {
			dport = fmt.Sprintf("%v", r.PrivatePortStart)
		} else {
			dport = fmt.Sprintf("%v-%v", r.PrivatePortStart, r.PrivatePortEnd)
		}

		pubNicName, err := utils.GetNicNameByMac(r.PublicMac)
		utils.PanicOnError(err)

		existed := false
		if currentRule := getRule(tree, des); currentRule != nil {
			if pip := currentRule.Getf("translation address %v", r.PrivateIp); pip == nil {
				currentRule.Delete()
			} else {
				existed = true
			}
		}
		if !existed {
			tree.SetDnat(
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("destination address %v", r.VipIp),
				fmt.Sprintf("destination port %v", sport),
				fmt.Sprintf("inbound-interface any"),
				fmt.Sprintf("protocol %v", strings.ToLower(r.ProtocolType)),
				fmt.Sprintf("translation address %v", r.PrivateIp),
				fmt.Sprintf("translation port %v", dport),
			)
		} else {
			log.Debugf("dnat rule %s exists, skip it", des)
		}

		reject := makeAllowCidrRejectDescription(r)
		existed = false
		if fr := tree.FindFirewallRuleByDescription(pubNicName, "in", reject); fr != nil {
			if pip := fr.Getf("destination address %v", r.PrivateIp); pip == nil {
				fr.Delete()
			} else {
				existed = true
			}
		}

		if !existed {
			if r.AllowedCidr != "" && r.AllowedCidr != "0.0.0.0/0" {
				tree.SetZStackFirewallRuleOnInterface(pubNicName, "behind", "in",
					"action reject",
					fmt.Sprintf("source address !%v", r.AllowedCidr),
					fmt.Sprintf("description %v", reject),
					// NOTE: the destination is private IP
					// because the destination address is changed by the dnat rule
					fmt.Sprintf("destination address %v", r.PrivateIp),
					fmt.Sprintf("destination port %v", dport),
					fmt.Sprintf("protocol %s", strings.ToLower(r.ProtocolType)),
					"state new enable",
				)
			}
		} else {
			log.Debugf("firewall rule %s exists, skip it", reject)
		}

		des = makeDnatDescription(r)
		existed = false
		if fr := tree.FindFirewallRuleByDescription(pubNicName, "in", des); fr != nil {
			if pip := fr.Getf("destination address %v", r.PrivateIp); pip == nil {
				fr.Delete()
			} else {
				existed = true
			}
		}

		if !existed {
			if r.AllowedCidr != "" && r.AllowedCidr != "0.0.0.0/0" {
				tree.SetZStackFirewallRuleOnInterface(pubNicName, "behind", "in",
					"action accept",
					fmt.Sprintf("source address %v", r.AllowedCidr),
					fmt.Sprintf("description %v", des),
					// NOTE: the destination is private IP
					// because the destination address is changed by the dnat rule
					fmt.Sprintf("destination address %v", r.PrivateIp),
					fmt.Sprintf("destination port %v", dport),
					fmt.Sprintf("protocol %s", strings.ToLower(r.ProtocolType)),
					"state new enable",
				)
			} else {
				tree.SetZStackFirewallRuleOnInterface(pubNicName, "behind", "in",
					"action accept",
					fmt.Sprintf("description %v", des),
					fmt.Sprintf("destination address %v", r.PrivateIp),
					fmt.Sprintf("destination port %v", dport),
					fmt.Sprintf("protocol %s", strings.ToLower(r.ProtocolType)),
					"state new enable",
				)
			}
		} else {
			log.Debugf("firewall rule %s exists, skip it", des)
		}

		tree.AttachFirewallToInterface(pubNicName, "in")
	}
}

func setDnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &setDnatCmd{}
	ctx.GetCommand(cmd)

	return setDnat(cmd)
}

func setDnat(cmd *setDnatCmd) interface{} {
	if utils.IsSkipVyosIptables() {
		for _, r := range cmd.Rules {
			pfMap[r.Uuid] = r
		}
		err := syncPortForwardingRules()
		utils.PanicOnError(err)

	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		setRuleInTree(tree, cmd.Rules)
		tree.Apply(false)
	}

	return nil
}

func removeDnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &removeDnatCmd{}
	ctx.GetCommand(cmd)

	return removeDnat(cmd)
}

func removeDnat(cmd *removeDnatCmd) interface{} {
	if utils.IsSkipVyosIptables() {
		for _, r := range cmd.Rules {
			delete(pfMap, r.Uuid)
		}
		err := syncPortForwardingRules()
		utils.PanicOnError(err)
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		for _, r := range cmd.Rules {
			des := makeDnatDescription(r)
			if c := getRule(tree, des); c != nil {
				c.Delete()
			} else {
				des = makeOrphanDnatDescription(r)
				if c := getRule(tree, des); c != nil {
					c.Delete()
				}
			}

			pubNicName, err := utils.GetNicNameByMac(r.PublicMac)
			utils.PanicOnError(err)
			if fr := tree.FindFirewallRuleByDescription(pubNicName, "in", des); fr != nil {
				fr.Delete()
			}

			des = makeAllowCidrRejectDescription(r)
			if fr := tree.FindFirewallRuleByDescription(pubNicName, "in", des); fr != nil {
				fr.Delete()
			}
		}
		tree.Apply(false)
	}

	for _, r := range cmd.Rules {
		proto := utils.IPTABLES_PROTO_UDP
		if r.ProtocolType != utils.IPTABLES_PROTO_UDP {
			proto = utils.IPTABLES_PROTO_TCP
		}
		t := utils.ConnectionTrackTuple{IsNat: false, IsDst: true, Ip: r.VipIp, Protocol: proto,
			PortStart: r.VipPortStart, PortEnd: r.VipPortEnd}
		t.CleanConnTrackConnection()
	}
	return nil
}

func init() {
	pfMap = make(map[string]dnatInfo, PortForwardingInfoMaxSize)
}

func DnatEntryPoint() {
	server.RegisterAsyncCommandHandler(CREATE_PORT_FORWARDING_PATH, server.VyosLock(setDnatHandler))
	server.RegisterAsyncCommandHandler(REVOKE_PORT_FORWARDING_PATH, server.VyosLock(removeDnatHandler))
	server.RegisterAsyncCommandHandler(SYNC_PORT_FORWARDING_PATH, server.VyosLock(syncDnatHandler))
}
