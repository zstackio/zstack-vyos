package plugin

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"path/filepath"
	"strings"
	"zstack-vyos/server"
	"zstack-vyos/utils"

	"github.com/fatih/structs"
	log "github.com/sirupsen/logrus"
	/*log "github.com/sirupsen/logrus"*/)

const (
	ENABLE_PIMD_PATH  = "/pimd/enable"
	DISABLE_PIMD_PATH = "/pimd/disable"
	GET_MROUTE_PATH   = "/pimd/route"
)

func getPimdConfDir() string {
	return filepath.Join(utils.GetUserHomePath(), "pimd/")
}

func getPimdConfPath() string {
	return filepath.Join(utils.GetUserHomePath(), "/pimd/pimd.conf")
}

func getPimdBinPath() string {
	return filepath.Join(utils.GetThirdPartyBinPath(), "pimd")
}

func getPimdHaScript() string {
	return filepath.Join(utils.GetZvrRootPath(), "keepalived/script/pimd.sh")
}

type rendezvousPointInfo struct {
	RpAddress     string `json:"rpAddress"`
	GroupAddress  string `json:"groupAddress"`
	SourceAddress string `json:"sourceAddress"`
}

type enablePimdCmd struct {
	Rps []rendezvousPointInfo `json:"rps"`
}

type disablePimdCmd struct {
}

type mRouteInfo struct {
	SourceAddress     string `json:"sourceAddress"`
	GroupAddress      string `json:"groupAddress"`
	IngressInterfaces string `json:"ingressInterfaces"`
	EgressInterfaces  string `json:"egressInterfaces"`
}

type getMrouteRsp struct {
	Routes []mRouteInfo `json:"routes"`
}

type getMrouteCmd struct {
}

type pimdAddNic struct{}

var pimdEnable bool

func init() {
	RegisterAddNicCallback(&pimdAddNic{})
}

func makePimdFirewallRuleDescription(name, nicname string) string {
	return fmt.Sprintf("%s-for-%s", name, nicname)
}

func stopPimd() {
	pid, err := utils.FindFirstPIDByPSExtern(true, getPimdBinPath())
	if err == nil && pid != 0 {
		utils.KillProcess(pid)
	}

	utils.Truncate(getPimdConfPath(), 0)
}

func updatePimdConf(cmd *enablePimdCmd) bool {
	bash := utils.Bash{
		Command: fmt.Sprintf("mkdir -p %s", getPimdConfDir()),
		NoLog:   true,
	}
	bash.Run()

	conf := `# Bigger value means  "higher" priority
#bsr-candidate $YOUR_BSR_CANDIDATE_IP priority 5
# Smaller value means "higher" priority
#rp-candidate  $YOUR_RP_CANDIDATE_IP time 30 priority 20
#    group-prefix 224.0.0.0 masklen 4

# Static rendezvous point
{{range .Rps}}
rp-address {{.RpAddress}} {{.GroupAddress}}
{{ end }}`

	var buf bytes.Buffer
	var m map[string]interface{}

	oldChecksum, _ := getFileChecksum(getPimdConfPath())
	tmpl, err := template.New("conf").Parse(conf)
	utils.PanicOnError(err)
	m = structs.Map(cmd)
	err = tmpl.Execute(&buf, m)
	utils.PanicOnError(err)
	err = ioutil.WriteFile(getPimdConfPath(), buf.Bytes(), 0755)
	utils.PanicOnError(err)
	newChecksum, _ := getFileChecksum(getPimdConfPath())

	log.Debugf("pimd config file: %s, old checksum:%s, new checksum:%s", getPimdConfPath(), oldChecksum, newChecksum)

	return !strings.EqualFold(oldChecksum, newChecksum)
}

func (pimd *pimdAddNic) AddNic(nic string) error {
	if pimdEnable == false {
		return nil
	}

	if utils.IsSkipVyosIptables() {
		table := utils.NewIpTables(utils.FirewallTable)

		var rules []*utils.IpTableRule

		rule := utils.NewIpTableRule(utils.GetRuleSetName(nic, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_PIMD).SetInNic(nic)
		rules = append(rules, rule)

		rule = utils.NewIpTableRule(utils.GetRuleSetName(nic, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_IGMP).SetInNic(nic)
		rules = append(rules, rule)

		table.AddIpTableRules(rules)
		return table.Apply()
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		des := makePimdFirewallRuleDescription(nic, "pimd")
		if r := tree.FindFirewallRuleByDescription(nic, "local", des); r == nil {
			tree.SetZStackFirewallRuleOnInterface(nic, "front", "local",
				fmt.Sprintf("description %v", des),
				"protocol pim",
				"action accept",
			)
		}

		des = makePimdFirewallRuleDescription(nic, "igmp")
		if r := tree.FindFirewallRuleByDescription(nic, "local", des); r == nil {
			tree.SetZStackFirewallRuleOnInterface(nic, "front", "local",
				fmt.Sprintf("description %v", des),
				"protocol igmp",
				"action accept",
			)
		}

		tree.AttachFirewallToInterface(nic, "local")

		des = makePimdFirewallRuleDescription("multiast", nic)
		if r := tree.FindFirewallRuleByDescription(nic, "in", des); r == nil {
			tree.SetZStackFirewallRuleOnInterface(nic, "front", "in",
				fmt.Sprintf("description %v", des),
				"destination address 224.0.0.0/4",
				"state new enable",
				"state established enable",
				"state related enable",
				"action accept",
			)
		}
		tree.AttachFirewallToInterface(nic, "in")

		tree.Apply(false)
	}

	restartPimd(true)

	return nil
}

func getPimdFirewallByNic(nics map[string]utils.Nic) []*utils.IpTableRule {
	var rules []*utils.IpTableRule
	for _, nic := range nics {
		/* pimd rule */
		rule := utils.NewIpTableRule(utils.GetRuleSetName(nic.Name, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_PIMD)
		rules = append(rules, rule)

		rule = utils.NewIpTableRule(utils.GetRuleSetName(nic.Name, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_IGMP)
		rules = append(rules, rule)

		rule = utils.NewIpTableRule(utils.GetRuleSetName(nic.Name, utils.RULESET_IN))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetDstIp("224.0.0.0/4")
		rule.SetState([]string{utils.IPTABLES_STATE_NEW, utils.IPTABLES_STATE_RELATED, utils.IPTABLES_STATE_ESTABLISHED})
		rules = append(rules, rule)
	}

	return rules
}

func addPimdFirewallByIptables(nics map[string]utils.Nic) error {
	table := utils.NewIpTables(utils.FirewallTable)
	oldRules := utils.GetPimdIpTableRule(table)
	table.RemoveIpTableRule(oldRules)

	var rules []*utils.IpTableRule
	rules = getPimdFirewallByNic(nics)

	if len(rules) > 0 {
		table.AddIpTableRules(rules)
		return table.Apply()
	}

	return nil
}

func restartPimd(force bool) {
	pid, err := utils.FindFirstPIDByPSExtern(true, getPimdBinPath())
	if err == nil && pid != 0 {
		/* if pimd is running, restart it if force restart */
		if !force {
			return
		}

		utils.KillProcess(pid)
	}

	bash := utils.Bash{
		Command: fmt.Sprintf("sudo %s -c %s", getPimdBinPath(), getPimdConfPath()),
	}

	bash.RunWithReturn()
	bash.PanicIfError()
}

func enablePimdHandler(ctx *server.CommandContext) interface{} {
	cmd := &enablePimdCmd{}
	ctx.GetCommand(cmd)

	/* enable firewall */
	nics, _ := utils.GetAllNics()
	if utils.IsSkipVyosIptables() {
		err := addPimdFirewallByIptables(nics)
		utils.PanicOnError(err)
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		for _, nic := range nics {
			des := makePimdFirewallRuleDescription(nic.Name, "pimd")
			if r := tree.FindFirewallRuleByDescription(nic.Name, "local", des); r == nil {
				tree.SetZStackFirewallRuleOnInterface(nic.Name, "front", "local",
					fmt.Sprintf("description %v", des),
					"protocol pim",
					"action accept",
				)
			}

			des = makePimdFirewallRuleDescription(nic.Name, "igmp")
			if r := tree.FindFirewallRuleByDescription(nic.Name, "local", des); r == nil {
				tree.SetZStackFirewallRuleOnInterface(nic.Name, "front", "local",
					fmt.Sprintf("description %v", des),
					"protocol igmp",
					"action accept",
				)
			}

			tree.AttachFirewallToInterface(nic.Name, "local")

			des = makePimdFirewallRuleDescription("multiast", nic.Name)
			if r := tree.FindFirewallRuleByDescription(nic.Name, "in", des); r == nil {
				tree.SetZStackFirewallRuleOnInterface(nic.Name, "behind", "in",
					fmt.Sprintf("description %v", des),
					"destination address 224.0.0.0/4",
					"state new enable",
					"state established enable",
					"state related enable",
					"action accept",
				)
			}
			tree.AttachFirewallToInterface(nic.Name, "in")
		}
		tree.Apply(false)
	}

	/* generate pimd.conf */
	changed := updatePimdConf(cmd)
	restartPimd(changed)

	pimdEnable = true

	writePimdHaScript(true)

	return nil
}

func removePimdFirewallByIptables(nics map[string]utils.Nic) error {
	table := utils.NewIpTables(utils.FirewallTable)
	oldRules := getPimdFirewallByNic(nics)
	table.RemoveIpTableRule(oldRules)

	return table.Apply()
}

func disablePimdHandler(ctx *server.CommandContext) interface{} {
	cmd := &disablePimdCmd{}
	ctx.GetCommand(cmd)

	nics, _ := utils.GetAllNics()
	if utils.IsSkipVyosIptables() {
		removePimdFirewallByIptables(nics)
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		for _, nic := range nics {
			des := makePimdFirewallRuleDescription(nic.Name, "pimd")
			if r := tree.FindFirewallRuleByDescription(nic.Name, "local", des); r != nil {
				r.Delete()
			}

			des = makePimdFirewallRuleDescription(nic.Name, "igmp")
			if r := tree.FindFirewallRuleByDescription(nic.Name, "local", des); r != nil {
				r.Delete()
			}

			des = makePimdFirewallRuleDescription("multiast", nic.Name)
			if r := tree.FindFirewallRuleByDescription(nic.Name, "in", des); r != nil {
				r.Delete()
			}
		}
		tree.Apply(false)
	}

	stopPimd()

	pimdEnable = false

	writePimdHaScript(false)

	return nil
}

func getMrouteHandler(ctx *server.CommandContext) interface{} {
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo ip mroute"),
	}

	_, out, _, _ := bash.RunWithReturn()
	if out == "" {
		return getMrouteRsp{Routes: nil}
	}

	/* in different version of ip
	line of mroute is:
	(10.86.5.99, 239.1.1.1)          Iif: eth0       Oifs: eth1 pimreg
	or
	(172.24.202.204,239.255.255.250) Iif: eth0       Oifs: pimreg  State: resolved
	*/
	routes := []mRouteInfo{}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var ingress, egress []string
		line = strings.Split(line, "State")[0]
		src := strings.Split(line, ",")[0]
		src = strings.TrimSpace(src)
		src = strings.TrimPrefix(src, "(")
		remain := strings.Split(line, ",")[1]

		group := strings.Split(remain, ")")[0]
		group = strings.TrimSpace(group)
		remain = strings.Split(remain, ")")[1]

		in := false
		out := false
		items := strings.Split(remain, " ")

		for _, item := range items {
			if item == " " || item == "" {
				continue
			}

			if item == "pimreg" {
				break
			}

			if item == "Iif:" {
				in = true
				continue
			}
			if item == "Oifs:" {
				out = true
				in = false
				continue
			}

			if in {
				item = strings.TrimSuffix(item, ",")
				ingress = append(ingress, item)
				continue
			}

			if out {
				item = strings.TrimSuffix(item, ",")
				egress = append(egress, item)
				continue
			}
		}

		route := mRouteInfo{SourceAddress: src, GroupAddress: group, IngressInterfaces: strings.Join(ingress, " "),
			EgressInterfaces: strings.Join(egress, " ")}
		routes = append(routes, route)
	}

	return getMrouteRsp{Routes: routes}
}

func writePimdHaScript(enable bool) {
	if !utils.IsHaEnabled() {
		return
	}

	var conent string
	if enable {
		conent = "sudo /opt/vyatta/sbin/pimd -l"
	} else {
		conent = "echo 'no pimd configured'"
	}

	err := ioutil.WriteFile(getPimdHaScript(), []byte(conent), 0755)
	utils.PanicOnError(err)
}

func PimdEntryPoint() {
	server.RegisterAsyncCommandHandler(ENABLE_PIMD_PATH, server.VyosLock(enablePimdHandler))
	server.RegisterAsyncCommandHandler(DISABLE_PIMD_PATH, server.VyosLock(disablePimdHandler))
	server.RegisterAsyncCommandHandler(GET_MROUTE_PATH, getMrouteHandler)
}
