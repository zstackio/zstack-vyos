package plugin

import (
	"zvr/server"
	"zvr/utils"
	"fmt"
	log "github.com/Sirupsen/logrus"
)

const (
	REMOVE_DNS_PATH = "/removedns"
	SET_DNS_PATH = "/setdns"
	SET_VPNDNS_PATH = "/setvpcdns"
)

type dnsInfo struct {
	DnsAddress string `json:"dnsAddress"`
	NicMac string `json:"nicMac"`
}

type setDnsCmd struct {
	Dns []dnsInfo `json:"dns"`
}

type removeDnsCmd struct {
	Dns []dnsInfo `json:"dns"`
}

type setVpcDnsCmd struct {
	Dns []string `json:"dns"`
	NicMac []string `json:"nicMac"`
}

var (
	dnsServers = map[string]string{}
	nicNames   = map[string]string{}
)

func makeDnsFirewallRuleDescription(nicname string) string {
	return fmt.Sprintf("DNS-for-%s", nicname)
}

func setDnsFirewallRules(nicName string) error {
	rule := utils.NewIptablesRule(utils.UDP, "", "", 0, 53, nil, utils.RETURN, utils.DnsRuleComment)
	utils.InsertFireWallRule(nicName, rule, utils.LOCAL)
	rule = utils.NewIptablesRule(utils.TCP, "", "", 0, 53, nil, utils.RETURN, utils.DnsRuleComment)
	utils.InsertFireWallRule(nicName, rule, utils.LOCAL)
	return nil
}

func removeDnsFirewallRules(nicName string) error {
	utils.DeleteLocalFirewallRuleByComment(nicName, utils.DnsRuleComment)
	return nil
}

func setDnsHandler(ctx *server.CommandContext) interface{} {
	tree := server.NewParserFromShowConfiguration().Tree

	cmd := &setDnsCmd{}
	ctx.GetCommand(cmd)

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
		eth, err := utils.GetNicNameByMac(mac); utils.PanicOnError(err)
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

	for _, info := range cmd.Dns {
		delete(dnsServers, info.DnsAddress)
	}

	dnsConf := NewDnsmasq(nicNames, dnsServers)
	dnsConf.RestartDnsmasq()

	return nil
}

func setVpcDnsHandler(ctx *server.CommandContext) interface{} {
	tree := server.NewParserFromShowConfiguration().Tree

	cmd := &setVpcDnsCmd{}
	ctx.GetCommand(cmd)

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
	for _, mac := range cmd.NicMac{
		eth, err := utils.GetNicNameByMac(mac); utils.PanicOnError(err)
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

func addDnsNic(nicName string)  {
	if _, ok := nicNames[nicName]; !ok {
		log.Debugf("add new dns nic [%s]", nicName)
		nicNames[nicName] = nicName
		dnsConf := NewDnsmasq(nicNames, dnsServers)
		dnsConf.RestartDnsmasq()
	} else {
		log.Debugf("dns nic [%s] already added", nicName)
	}
}

func DnsEntryPoint() {
	server.RegisterAsyncCommandHandler(SET_DNS_PATH, server.VyosLock(setDnsHandler))
	server.RegisterAsyncCommandHandler(REMOVE_DNS_PATH, server.VyosLock(removeDnsHandler))
	server.RegisterAsyncCommandHandler(SET_VPNDNS_PATH, server.VyosLock(setVpcDnsHandler))
}
