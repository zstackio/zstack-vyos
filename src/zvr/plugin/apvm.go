package plugin

import (
	"zvr/utils"
	"zvr/server"
	"fmt"
	"github.com/pkg/errors"
	"strings"
)

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
	cmd := &refreshFirewallCmd{}
	ctx.GetCommand(cmd)

	commands := make([]string, 0)
	nics, err := utils.GetAllNics(); utils.PanicOnError(err)

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
		ruleSetName := fmt.Sprintf("%s-rules", nicname)

		commands = append(commands, fmt.Sprintf("$SET firewall name %s default-action accept", ruleSetName))
		for i, rule := range rules {
			if rule.SourceIp != "" {
				commands = append(commands, fmt.Sprintf("$SET firewall name %s rule %v source address %v/32",
					ruleSetName, i, rule.SourceIp))
			}

			if rule.DestIp != "" {
				commands = append(commands, fmt.Sprintf("$SET firewall name %s rule %v destination address %v/32",
					ruleSetName, i, rule.DestIp))
			}

			commands = append(commands, fmt.Sprintf("$SET firewall name %s rule %v destination port %v-%v",
				ruleSetName, i, rule.StartPort, rule.EndPort))
			commands = append(commands, fmt.Sprintf("$SET firewall name %s rule %v state new enable",
				ruleSetName, i))

			if rule.Protocol == "all" {
				commands = append(commands, fmt.Sprintf("$SET firewall name %s rule %v protocol tcp_udp",
					ruleSetName, i))
			} else if rule.Protocol == "udp" {
				commands = append(commands, fmt.Sprintf("$SET firewall name %s rule %v protocol udp",
					ruleSetName, i))
			} else if rule.Protocol == "tcp" {
				commands = append(commands, fmt.Sprintf("$SET firewall name %s rule %v protocol tcp",
					ruleSetName, i))
			}
		}
		commands = append(commands, fmt.Sprintf("$SET interfaces ethernet %v firewall local name %v", nicname, ruleSetName))
	}

	server.RunVyosScriptAsUserVyos(strings.Join(commands, "\n"))

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
