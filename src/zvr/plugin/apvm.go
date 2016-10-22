package plugin

import (
	"zvr/utils"
	"zvr/server"
	"fmt"
	"io/ioutil"
	"encoding/json"
	"github.com/pkg/errors"
	"strings"
)

const (
	APVM_REFRESH_FIREWALL_PATH = "/appliancevm/refreshfirewall"
	APVM_ECHO_PATH = "/appliancevm/echo"
	APVM_INIT_PATH = "/appliancevm/init"
	BOOTSTRAP_INFO_CACHE = "/var/lib/zstack/bootstrap-info.json"
)

type firewallRule struct {
	Protocol string `json:"protocol"`
	StartPort string `json:"startPort"`
	EndPort string `json:"endPort"`
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

	commands = append(commands, "$SET firewall name default default-action drop")
	count := 1
	commands = append(commands, fmt.Sprintf("$SET firewall name default rule %v action accept", count))
	commands = append(commands, fmt.Sprintf("$SET firewall name default rule %v state established enable", count))
	commands = append(commands, fmt.Sprintf("$SET firewall name default rule %v state state related enable", count))
	count ++
	commands = append(commands, fmt.Sprintf("$SET firewall name default rule %v action accept", count))
	commands = append(commands, fmt.Sprintf("$SET firewall name default rule %v protocol icmp", count))
	for _, nic := range nics {
		commands = append(commands, fmt.Sprintf("$SET interfaces ethernet %s firewall local name default", nic.Name))
		commands = append(commands, fmt.Sprintf("$SET interfaces ethernet %s firewall in name default", nic.Name))
	}

	// only allow ssh traffic on eth0, disable on others
	content, err := ioutil.ReadFile(BOOTSTRAP_INFO_CACHE); utils.PanicOnError(err)
	info := make(map[string]interface{})
	utils.PanicOnError(json.Unmarshal(content, info))
	sshport := info["sshPort"].(float64)
	utils.Assert(sshport != 0, "sshport not found in bootstrap info")
	commands = append(commands, "$SET firewall name sshon default action accept")
	commands = append(commands, fmt.Sprintf("$SET firewall name sshon rule 1 destination port %v", int(sshport)))
	commands = append(commands, "$SET interfaces ethernet eth0 firewall local name sshon")

	commands = append(commands, "$SET firewall name sshoff default action reject")
	commands = append(commands, fmt.Sprintf("$SET firewall name sshoff rule 1 destination port %v", int(sshport)))
	for _, nic := range nics {
		if nic.Name == "eth0" {
			continue
		}

		commands = append(commands, fmt.Sprintf("$SET interfaces ethernet %v firewall local name sshoff", nic.Name))
	}

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
