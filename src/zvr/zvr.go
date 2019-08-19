package main

import (
	"strconv"
	"zvr/server"
	"zvr/plugin"
	"zvr/utils"
	"fmt"
	"flag"
	"os"
	log "github.com/Sirupsen/logrus"
)

const (
	zstackRuleNumberFront = 1000
)

func loadPlugins()  {
	plugin.ApvmEntryPoint()
	plugin.DhcpEntryPoint()
	plugin.MiscEntryPoint()
	plugin.DnsEntryPoint()
	plugin.SnatEntryPoint()
	plugin.DnatEntryPoint()
	plugin.VipEntryPoint()
	plugin.EipEntryPoint()
	plugin.LbEntryPoint()
	plugin.IPsecEntryPoint()
	plugin.ConfigureNicEntryPoint()
	plugin.RouteEntryPoint()
	plugin.ZsnEntryPoint()
	plugin.PrometheusEntryPoint()
	plugin.OspfEntryPoint()
	plugin.VyosHaEntryPoint()
	plugin.FlowMeterEntryPoint()
	plugin.PolicyRouteEntryPoint()
	plugin.FirewallEntryPoint()
}

var options server.Options

func abortOnWrongOption(msg string) {
	fmt.Println(msg)
	flag.Usage()
	os.Exit(1)
}

func parseCommandOptions() {
	options = server.Options{}
	flag.StringVar(&options.Ip, "ip", "", "The IP address the server listens on")
	flag.UintVar(&options.Port, "port", 7272, "The port the server listens on")
	flag.UintVar(&options.ReadTimeout, "readtimeout", 10, "The socket read timeout")
	flag.UintVar(&options.WriteTimeout, "writetimeout", 10, "The socket write timeout")
	flag.StringVar(&options.LogFile, "logfile", "zvr.log", "The log file path")

	flag.Parse()

	if options.Ip == "" {
		abortOnWrongOption("error: the options 'ip' is required")
	}

	server.SetOptions(options)
}

func configureZvrFirewall() {
	if utils.IsSkipVyosIptables() {
		err := utils.InitNicFirewall("eth0", options.Ip, true, utils.ACCEPT)
		if err != nil {
			log.Debugf("zvr configureZvrFirewall failed %s", err.Error())
		}
		return
	}

	tree := server.NewParserFromShowConfiguration().Tree

	/* add description to avoid duplicated firewall rule when reconnect vr */
	des := "management-port-rule"
	if r := tree.FindFirewallRuleByDescription("eth0", "local", des); r != nil {
		r.Delete()
	}

	tree.SetFirewallOnInterface("eth0", "local",
		fmt.Sprintf("destination address %v", options.Ip),
		fmt.Sprintf("destination port %v", options.Port),
		"protocol tcp",
		"action accept",
		fmt.Sprintf("description %s", des),
	)

	tree.Apply(false)
}

func getIcmpRule(t *server.VyosConfigNode) int {
	for _, cn := range t.Children() {
		number, _ := strconv.Atoi(cn.Name())
		if number > zstackRuleNumberFront {
			continue
		}

		if cn.Get("action accept")!= nil && cn.Get("protocol icmp") != nil {
			return number
		}
	}

	return 0
}

func getStateRule(t *server.VyosConfigNode) (int, string) {
	for _, cn := range t.Children() {
		number, _ := strconv.Atoi(cn.Name())
		if number > zstackRuleNumberFront {
			continue
		}

		if cn.Get("action accept") != nil && cn.Get("state established enable") != nil && cn.Get("state related enable") != nil {
			if cn.Get("description") != nil || cn.Get("source") != nil {
				continue
			}

			if cn.Get("state invalid enable") != nil && cn.Get("state new enable") != nil {
				return number, "private"
			}

			return number, "public"
		}
	}

	return 0, ""
}

func moveNicInForwardFirewall() {
	tree := server.NewParserFromShowConfiguration().Tree

	//move zvrboot nic firewall config to 4000 behind
	nics, _ := utils.GetAllNics()
	changed := false
	for _, nic := range nics {
		eNode := tree.Getf("firewall name %s.in rule", nic.Name)
		if eNode == nil {
			continue
		}

		if ruleNumber, nicType := getStateRule(eNode); ruleNumber != 0 {
			tree.Deletef("firewall name %s.in rule %v", nic.Name, ruleNumber)
			if nicType == "Private" {
				tree.SetZStackFirewallRuleOnInterface(nic.Name, "behind", "in",
					"action accept",
					"state established enable",
					"state related enable",
					"state invalid enable",
					"state new enable",
				)
			} else {
				tree.SetZStackFirewallRuleOnInterface(nic.Name, "behind", "in",
					"action accept",
					"state established enable",
					"state related enable",
				)
			}
			changed = true
		}

		if ruleNumber := getIcmpRule(eNode); ruleNumber != 0 {
			tree.Deletef("firewall name %s.in rule %v", nic.Name, ruleNumber)
			tree.SetZStackFirewallRuleOnInterface(nic.Name, "behind", "in",
				"action accept",
				"protocol icmp",
			)
			changed = true
		}

		if eNode.Get("9999") == nil {
			tree.SetFirewallWithRuleNumber(nic.Name, "in", 9999,
				"action accept",
				"state new enable",
			)
			changed = true
		}
	}

	if changed {
		tree.Apply(false)
	}
}

func main()  {

	parseCommandOptions()
	utils.InitLog(options.LogFile, false)
	utils.InitBootStrapInfo()
	plugin.InitHaNicState()
	utils.InitNatRule()
	loadPlugins()
	server.VyosLockInterface(configureZvrFirewall)()
	server.VyosLockInterface(moveNicInForwardFirewall)()

	server.Start()
}
