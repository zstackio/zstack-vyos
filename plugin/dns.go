package plugin

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
)

const (
	REMOVE_DNS_PATH = "/removedns"
	SET_DNS_PATH    = "/setdns"
	SET_VPNDNS_PATH = "/setvpcdns"
)

type dnsInfo struct {
	DnsAddress string `json:"dnsAddress"`
	NicMac     string `json:"nicMac"`
}

type setDnsCmd struct {
	Dns []dnsInfo `json:"dns"`
}

type removeDnsCmd struct {
	Dns []dnsInfo `json:"dns"`
}

type setVpcDnsCmd struct {
	Dns    []string `json:"dns"`
	NicMac []string `json:"nicMac"`
}

var dnsServers map[string]string
var nicNames map[string]string

func makeDnsFirewallRuleDescription(nicname string) string {
	return fmt.Sprintf("DNS-for-%s", nicname)
}

func setDnsFirewallRules(nicName string) error {
	table := utils.NewIpTables(utils.FirewallTable)

	var rules []*utils.IpTableRule

	rule := utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule.SetProto(utils.IPTABLES_PROTO_UDP).SetDstPort("53")
	rules = append(rules, rule)

	rule = utils.NewIpTableRule(utils.GetRuleSetName(nicName, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
	rule.SetProto(utils.IPTABLES_PROTO_TCP).SetDstPort("53")
	rules = append(rules, rule)

	table.AddIpTableRules(rules)
	return table.Apply()
}

func removeDnsFirewallRules(nicName string) error {
	table := utils.NewIpTables(utils.FirewallTable)
	dnsRules := utils.GetDnsIpTableRule(table)
	for _, r := range dnsRules {
		if r.GetChainName() == utils.GetRuleSetName(nicName, utils.RULESET_LOCAL) {
			table.RemoveIpTableRule([]*utils.IpTableRule{r})
		}
	}

	return table.Apply()
}

func setDnsHandler(ctx *server.CommandContext) interface{} {
	cmd := &setDnsCmd{}
	ctx.GetCommand(cmd)

	return setDns(cmd)
}

func setDns(cmd *setDnsCmd) interface{} {
	tree := server.NewParserFromShowConfiguration().Tree
	dnsByMac := make(map[string][]dnsInfo)
	for _, info := range cmd.Dns {
		dns := dnsByMac[info.NicMac]
		if dns == nil {
			dns = make([]dnsInfo, 0)
		}
		dns = append(dns, info)
		dnsByMac[info.NicMac] = dns
	}

	dnsServers = map[string]string{}
	nicNames = map[string]string{}

	/* dns is ordered in management node, should not be changed in vyos */
	for _, info := range cmd.Dns {
		dnsServers[info.DnsAddress] = info.DnsAddress
	}

	for mac, _ := range dnsByMac {
		eth, err := utils.GetNicNameByMac(mac)
		utils.PanicOnError(err)
		nicNames[eth] = eth

		if utils.IsSkipVyosIptables() {
			setDnsFirewallRules(eth)
		} else {
			des := makeDnsFirewallRuleDescription(eth)
			if r := tree.FindFirewallRuleByDescription(eth, "local", des); r == nil {
				tree.SetFirewallOnInterface(eth, "local",
					fmt.Sprintf("description %v", des),
					"destination port 53",
					"protocol tcp_udp",
					"action accept",
				)

				tree.AttachFirewallToInterface(eth, "local")
			}
		}
	}

	tree.Apply(false)

	dnsConf := NewDnsmasq(nicNames, dnsServers)
	dnsConf.RestartDnsmasq()

	return nil
}

func removeDnsHandler(ctx *server.CommandContext) interface{} {
	cmd := &removeDnsCmd{}
	ctx.GetCommand(cmd)

	return removeDns(cmd)
}

func removeDns(cmd *removeDnsCmd) interface{} {
	for _, info := range cmd.Dns {
		delete(dnsServers, info.DnsAddress)
	}

	dnsConf := NewDnsmasq(nicNames, dnsServers)
	dnsConf.RestartDnsmasq()

	return nil
}

func setVpcDnsHandler(ctx *server.CommandContext) interface{} {
	cmd := &setVpcDnsCmd{}
	ctx.GetCommand(cmd)

	return setVpcDns(cmd)
}

func setVpcDns(cmd *setVpcDnsCmd) interface{} {
	tree := server.NewParserFromShowConfiguration().Tree

	/* remove old dns  */
	dnsServers = map[string]string{}
	nicNames = map[string]string{}
	priNics := utils.GetPrivteInterface()
	for _, priNic := range priNics {
		if utils.IsSkipVyosIptables() {
			removeDnsFirewallRules(priNic)
		} else {
			des := makeDnsFirewallRuleDescription(priNic)
			if r := tree.FindFirewallRuleByDescription(priNic, "local", des); r != nil {
				r.Delete()
			}
		}
	}

	/* add new configure */
	var nics []string
	for _, mac := range cmd.NicMac {
		eth, err := utils.GetNicNameByMac(mac)
		utils.PanicOnError(err)
		nics = append(nics, eth)
	}

	for _, nic := range nics {
		nicNames[nic] = nic
		if utils.IsSkipVyosIptables() {
			setDnsFirewallRules(nic)
		} else {
			des := makeDnsFirewallRuleDescription(nic)
			if r := tree.FindFirewallRuleByDescription(nic, "local", des); r == nil {
				tree.SetFirewallOnInterface(nic, "local",
					fmt.Sprintf("description %v", des),
					"destination port 53",
					"protocol tcp_udp",
					"action accept",
				)

				tree.AttachFirewallToInterface(nic, "local")
			}
		}
	}

	for _, dns := range cmd.Dns {
		dnsServers[dns] = dns
	}

	tree.Apply(false)

	dnsConf := NewDnsmasq(nicNames, dnsServers)
	dnsConf.RestartDnsmasq()

	return nil
}
func addDnsNic(nicName string) {
	if _, ok := nicNames[nicName]; !ok {
		log.Debugf("add new dns nic [%s]", nicName)
		nicNames[nicName] = nicName
		dnsConf := NewDnsmasq(nicNames, dnsServers)
		dnsConf.RestartDnsmasq()
	} else {
		log.Debugf("dns nic [%s] already added", nicName)
	}
}

func init() {
	dnsServers = map[string]string{}
	nicNames = map[string]string{}
}

func DnsEntryPoint() {
	server.RegisterAsyncCommandHandler(SET_DNS_PATH, server.VyosLock(setDnsHandler))
	server.RegisterAsyncCommandHandler(REMOVE_DNS_PATH, server.VyosLock(removeDnsHandler))
	server.RegisterAsyncCommandHandler(SET_VPNDNS_PATH, server.VyosLock(setVpcDnsHandler))
}
