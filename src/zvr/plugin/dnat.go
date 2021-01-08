package plugin

import (
	"zvr/server"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"zvr/utils"
	"strings"
)

const (
	CREATE_PORT_FORWARDING_PATH = "/createportforwarding"
	REVOKE_PORT_FORWARDING_PATH = "/revokeportforwarding"
	SYNC_PORT_FORWARDING_PATH = "/syncportforwarding"
	PortForwardingInfoMaxSize = 512
)

type dnatInfo struct {
	Uuid         string `json:"uuid"`
	VipPortStart int `json:"vipPortStart"`
	VipPortEnd int `json:"vipPortEnd"`
	PrivatePortStart int `json:"privatePortStart"`
	PrivatePortEnd int `json:"privatePortEnd"`
	ProtocolType string `json:"protocolType"`
	VipIp string `json:"vipIp"`
	PublicMac string `json:"publicMac"`
	PrivateIp string `json:"privateIp"`
	PrivateMac string `json:"privateMac"`
	AllowedCidr string `json:"allowedCidr"`
	SnatInboundTraffic bool `json:"snatInboundTraffic"`
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
	dnatRules := []utils.IptablesRule{}
	filterRules := make(map[string][]utils.IptablesRule)

	for _, r := range pfMap {
		pubNicName, err := utils.GetNicNameByMac(r.PublicMac); utils.PanicOnError(err)
		/* from ZStack side, port range is not supported */
		protocol := utils.TCP
		if r.ProtocolType != "TCP" {
			protocol = utils.UDP
		}
		if r.AllowedCidr != "" && r.AllowedCidr != "0.0.0.0/0" {
			ruleSpec := utils.NewIptablesRule(protocol, fmt.Sprintf("!%s", r.AllowedCidr), r.PrivateIp + "/32", 0, r.VipPortStart,
				[]string{utils.NEW}, utils.REJECT, fmt.Sprintf("%s%s-%d", utils.PortFordingRuleComment, r.VipIp, r.VipPortStart))
			filterRules[pubNicName] = append(filterRules[pubNicName], ruleSpec)
		}

		ruleSpec := utils.NewIptablesRule(protocol, "", r.PrivateIp + "/32", 0, r.VipPortStart,
			[]string{utils.NEW}, utils.RETURN, fmt.Sprintf("%s%s-%d", utils.PortFordingRuleComment, r.VipIp, r.VipPortStart))
		filterRules[pubNicName] = append(filterRules[pubNicName], ruleSpec)

		ruleSpec = utils.NewNatIptablesRule(protocol, "" , r.VipIp + "/32", 0, r.VipPortStart,
			nil, utils.DNAT, fmt.Sprintf("%s%s-%d", utils.PortFordingRuleComment, r.VipIp, r.VipPortStart), r.PrivateIp, r.PrivatePortStart)
		dnatRules = append(dnatRules, ruleSpec)
	}

	if err := utils.SyncNatRule(nil, dnatRules, utils.PortFordingRuleComment); err != nil {
		log.Warn("SyncNatRule for portforwarding failed %s", err.Error())
		utils.PanicOnError(err)
		return err
	}

	if err := utils.SyncFirewallRule(filterRules, utils.PortFordingRuleComment, utils.IN); err != nil {
		log.Warn("SyncFirewallRule for portforwarding failed %s", err.Error())
		utils.PanicOnError(err)
		return err
	}

	return nil
}

func syncDnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &syncDnatCmd{}
	ctx.GetCommand(cmd)

	pfMap = make(map[string]dnatInfo, PortForwardingInfoMaxSize)

	if utils.IsSkipVyosIptables() {
		for _, rule := range cmd.Rules {
			pfMap[rule.Uuid] = rule
		}
		syncPortForwardingRules()
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

		if (len(cmd.Rules) > 1) {
			pubNicName, err := utils.GetNicNameByMac(cmd.Rules[0].PublicMac); utils.PanicOnError(err)
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
		if currentRule := getRule(tree, des); currentRule != nil {
			log.Debugf("dnat rule %s exists, skip it", des)
			continue
		} else if currentRule := getRule(tree, makeOrphanDnatDescription(r)); currentRule != nil {
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

		pubNicName, err := utils.GetNicNameByMac(r.PublicMac); utils.PanicOnError(err)

		tree.SetDnat(
			fmt.Sprintf("description %v", des),
			fmt.Sprintf("destination address %v", r.VipIp),
			fmt.Sprintf("destination port %v", sport),
			fmt.Sprintf("inbound-interface any"),
			fmt.Sprintf("protocol %v", strings.ToLower(r.ProtocolType)),
			fmt.Sprintf("translation address %v", r.PrivateIp),
			fmt.Sprintf("translation port %v", dport),
		)

		reject := makeAllowCidrRejectDescription(r)
		if fr := tree.FindFirewallRuleByDescription(pubNicName, "in", reject); fr == nil {
			if r.AllowedCidr != "" && r.AllowedCidr != "0.0.0.0/0" {
				tree.SetZStackFirewallRuleOnInterface(pubNicName, "behind","in",
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
		}

		des = makeDnatDescription(r)
		if fr := tree.FindFirewallRuleByDescription(pubNicName, "in", des); fr == nil {
			if r.AllowedCidr != "" && r.AllowedCidr != "0.0.0.0/0" {
				tree.SetZStackFirewallRuleOnInterface(pubNicName, "behind","in",
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
				tree.SetZStackFirewallRuleOnInterface(pubNicName, "behind","in",
					"action accept",
					fmt.Sprintf("description %v", des),
					fmt.Sprintf("destination address %v", r.PrivateIp),
					fmt.Sprintf("destination port %v", dport),
					fmt.Sprintf("protocol %s", strings.ToLower(r.ProtocolType)),
					"state new enable",
				)
			}
		}

		tree.AttachFirewallToInterface(pubNicName, "in")
	}
}

func setDnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &setDnatCmd{}
	ctx.GetCommand(cmd)

	if utils.IsSkipVyosIptables() {
		for _, r := range cmd.Rules {
			pfMap[r.Uuid] = r
		}
		syncPortForwardingRules()
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

	if utils.IsSkipVyosIptables() {
		for _, r := range cmd.Rules {
			delete(pfMap, r.Uuid)
		}
		syncPortForwardingRules()
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

			pubNicName, err := utils.GetNicNameByMac(r.PublicMac); utils.PanicOnError(err)
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
		proto := "udp"
		if r.ProtocolType != "UDP" {
			proto = "tcp"
		}
		t := utils.ConnectionTrackTuple{IsNat:false, IsDst: true, Ip: r.VipIp, Protocol: proto,
			PortStart: r.VipPortStart, PortEnd: r.VipPortEnd}
		t.CleanConnTrackConnection()
	}
	return nil
}

func DnatEntryPoint() {
	pfMap = make(map[string]dnatInfo, PortForwardingInfoMaxSize)
	server.RegisterAsyncCommandHandler(CREATE_PORT_FORWARDING_PATH, server.VyosLock(setDnatHandler))
	server.RegisterAsyncCommandHandler(REVOKE_PORT_FORWARDING_PATH, server.VyosLock(removeDnatHandler))
	server.RegisterAsyncCommandHandler(SYNC_PORT_FORWARDING_PATH, server.VyosLock(syncDnatHandler))
}
