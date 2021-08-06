package plugin

import (
	"zvr/server"
)

// This plugin is largely to keep the mgmt server appliance vm
// logic unchanged

const (
	APVM_REFRESH_FIREWALL_PATH = "/appliancevm/refreshfirewall"
	APVM_ECHO_PATH = "/appliancevm/echo"
	APVM_INIT_PATH = "/appliancevm/init"
)

type firewallRule struct {
	Protocol string `json:"protocol"`
	StartPort int `json:"startPort"`
	EndPort int `json:"endPort"`
	AllowCidr string `json:"allowCidr"`
	SourceIp string `json:"sourceIp"`
	DestIp string `json:"destIp"`
	NicMac string `json:"nicMac"`
}

type refreshFirewallCmd struct {
	Rules []firewallRule
}

func apvmRefreshFirewallHandler(ctx *server.CommandContext) interface{} {
	/*
	cmd := &refreshFirewallCmd{}
	ctx.GetCommand(cmd)

	nics, err := utils.GetAllNics(); utils.PanicOnError(err)
	parser := server.NewParserFromShowConfiguration()
	tree := parser.Tree

	// configure rule for each interface
	ruleByNicnames := make(map[string][]firewallRule)
	for _, rule := range cmd.Rules {
		var nicname string
		if rule.DestIp != "" {
			nicname, err = utils.GetNicNameByIp(rule.DestIp); utils.PanicOnError(err)
		} else {
			nicname = func() string {
				for _, nic := range nics {
					if nic.Mac == rule.NicMac {
						return nic.Name
					}
				}

				panic(errors.Errorf("unable to find the nic[mac:%s] in the system", rule.NicMac))
			}()
		}

		rules := ruleByNicnames[nicname]
		if rules == nil {
			rules = make([]firewallRule, 0)
		}

		rules = append(rules, rule)
		ruleByNicnames[nicname] = rules
	}

	for nicname, rules := range ruleByNicnames {
		for _, rule := range rules {
			rs := make([]string, 0)

			if rule.SourceIp != "" {
				rs = append(rs, fmt.Sprintf("source address %v/32", rule.SourceIp))
			}

			if rule.DestIp != "" {
				rs = append(rs, fmt.Sprintf("destination address %v/32", rule.DestIp))
			}

			if rule.StartPort == rule.EndPort {
				rs = append(rs, fmt.Sprintf("destination port %v", rule.StartPort))
			} else {
				rs = append(rs, fmt.Sprintf("destination port %v-%v", rule.StartPort, rule.EndPort))
			}
			rs = append(rs, "state new enable")

			if rule.Protocol == "all" {
				rs = append(rs, "protocol tcp_udp")
			} else if rule.Protocol == "udp" {
				rs = append(rs, "protocol udp")
			} else if rule.Protocol == "tcp" {
				rs = append(rs, "protocol tcp")
			}
			rs = append(rs, "action accept")

			tree.SetFirewallOnInterface(nicname, "local", rs...)
		}

		tree.AttachFirewallToInterface(nicname, "local")
	}

	tree.Apply(false)
	*/

	// firewall is totally handled by ourselves, we
	// don't need mgmt server to instruct us; however,
	// to keep the mgmt server side code consistent,
	// we return success for every call
	return nil
}

func apvmEchoHandler(ctx *server.CommandContext) interface{} {
	return nil
}

func apvmInitHandler(ctx *server.CommandContext) interface{} {
	// nothing to do
	return nil
}

func ApvmEntryPoint() {
	server.RegisterSyncCommandHandler(APVM_ECHO_PATH, apvmEchoHandler)
	server.RegisterAsyncCommandHandler(APVM_REFRESH_FIREWALL_PATH, server.VyosLock(apvmRefreshFirewallHandler))
	server.RegisterAsyncCommandHandler(APVM_INIT_PATH, apvmInitHandler)
}
