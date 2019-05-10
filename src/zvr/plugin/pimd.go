package plugin

import (
	"html/template"
	"zvr/server"
	"zvr/utils"
	"fmt"
	"strings"
	"bytes"
	"io/ioutil"
	"github.com/fatih/structs"
	/*log "github.com/Sirupsen/logrus"*/
)

const (
	ENABLE_PIMD_PATH = "/pimd/enable"
	DISABLE_PIMD_PATH = "/pimd/disable"
	GET_MROUTE_PATH = "/pimd/route"

	PIMD_BINARY_PATH = "/opt/vyatta/sbin/pimd"
	PIMD_CONF_DIR = "/home/vyos/zvr/pimd/"
	PIMD_CONF_PATH = "/home/vyos/zvr/pimd/pimd.conf"
)

type rendezvousPointInfo struct {
	RpAddress string `json:"rpAddress"`
	GroupAddress string `json:"groupAddress"`
	SourceAddress string `json:"sourceAddress"`
}

type enablePimdCmd struct {
	Rps []rendezvousPointInfo `json:"rps"`
}


type disablePimdCmd struct {
}

type mRouteInfo struct {
	SourceAddress string `json:"sourceAddress"`
	GroupAddress string `json:"groupAddress"`
	IngressInterfaces string `json:"ingressInterfaces"`
	EgressInterfaces string `json:"egressInterfaces"`
}

type getMrouteRsp struct {
	Routes []mRouteInfo `json:"routes"`
}

type getMrouteCmd struct {
}

type pimdAddNic struct {}

var pimdEnable bool

func init()  {
	pimdEnable = false
	RegisterAddNicCallback(&pimdAddNic{})
}

func makePimdFirewallRuleDescription(name, nicname string) string {
	return fmt.Sprintf("%s-for-%s", name, nicname)
}

func stopPimd()  {
	pid, err := utils.FindFirstPIDByPSExtern(true, PIMD_BINARY_PATH)
	if err == nil && pid != 0 {
		utils.KillProcess(pid)
	}

}

func updatePimdConf(cmd *enablePimdCmd)  error {
	bash := utils.Bash{
		Command: fmt.Sprintf("mkdir -p %s", PIMD_CONF_DIR),
		NoLog: true,
	}
	bash.Run()

	conf := `# Bigger value means  "higher" priority
#bsr-candidate $YOUR_BSR_CANDIDATE_IP priority 5
# Smaller value means "higher" priority
#rp-candidate  $YOUR_RP_CANDIDATE_IP time 30 priority 20
#    group-prefix 224.0.0.0 masklen 4

# Static rendez-vous point
{{range .Rps}}
rp-address {{.RpAddress}} {{.GroupAddress}}
{{ end }}`

	var buf bytes.Buffer
	var m map[string]interface{}

	tmpl, err := template.New("conf").Parse(conf); utils.PanicOnError(err)
	m = structs.Map(cmd)
	err = tmpl.Execute(&buf, m); utils.PanicOnError(err)
	err = ioutil.WriteFile(PIMD_CONF_PATH, buf.Bytes(), 0755); utils.PanicOnError(err)

	return err
}

func (pimd *pimdAddNic) AddNic(nic string)  error {
	if pimdEnable == false {
		return nil
	}

	if utils.IsSkipVyosIptables() {
		rule := utils.NewIptablesRule("pimd", "", "", 0, 0, nil, utils.ACCEPT, utils.PIMDComment + nic)
		utils.InsertFireWallRule(nic, rule, utils.LOCAL)

		rule = utils.NewIptablesRule("igmp", "", "", 0, 0, nil, utils.ACCEPT, utils.PIMDComment + nic)
		utils.InsertFireWallRule(nic, rule, utils.LOCAL)
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		des := makePimdFirewallRuleDescription(nic, "pimd")
		if r := tree.FindFirewallRuleByDescription(nic, "local", des); r == nil {
			tree.SetFirewallOnInterface(nic, "local",
				fmt.Sprintf("description %v", des),
				"protocol pim",
				"action accept",
			)
		}

		des = makePimdFirewallRuleDescription(nic, "igmp")
		if r := tree.FindFirewallRuleByDescription(nic, "local", des); r == nil {
			tree.SetFirewallOnInterface(nic, "local",
				fmt.Sprintf("description %v", des),
				"protocol igmp",
				"action accept",
			)
		}

		tree.AttachFirewallToInterface(nic, "local")
		tree.Apply(false)
	}

	restartPimd()

	return nil
}

func addPimdFirewallByIptables(nics map[string]utils.Nic)  error{
	for _, nic := range nics {
		/* pimd rule */
		rule := utils.NewIptablesRule("pimd", "", "", 0, 0, nil, utils.ACCEPT, utils.PIMDComment + nic.Name)
		utils.InsertFireWallRule(nic.Name, rule, utils.LOCAL)

		rule = utils.NewIptablesRule("igmp", "", "", 0, 0, nil, utils.ACCEPT, utils.PIMDComment + nic.Name)
		utils.InsertFireWallRule(nic.Name, rule, utils.LOCAL)
	}

	return nil
}

func restartPimd() {
	pid, err := utils.FindFirstPIDByPSExtern(true, PIMD_BINARY_PATH)
	if err == nil && pid != 0 {
		utils.KillProcess(pid)
	}

	bash := utils.Bash{
		Command: fmt.Sprintf("sudo %s -c %s", PIMD_BINARY_PATH, PIMD_CONF_PATH),
	}

	bash.RunWithReturn(); bash.PanicIfError()
}

func enablePimdHandler(ctx *server.CommandContext) interface{} {
	cmd := &enablePimdCmd{}
	ctx.GetCommand(cmd)

	/* enable firewall */
	nics, _ := utils.GetAllNics()
	if utils.IsSkipVyosIptables() {
		addPimdFirewallByIptables(nics)
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		for _, nic := range nics {
			des := makePimdFirewallRuleDescription(nic.Name, "pimd")
			if r := tree.FindFirewallRuleByDescription(nic.Name, "local", des); r == nil {
				tree.SetFirewallOnInterface(nic.Name, "local",
					fmt.Sprintf("description %v", des),
					"protocol pim",
					"action accept",
				)
			}

			des = makePimdFirewallRuleDescription(nic.Name, "igmp")
			if r := tree.FindFirewallRuleByDescription(nic.Name, "local", des); r == nil {
				tree.SetFirewallOnInterface(nic.Name, "local",
					fmt.Sprintf("description %v", des),
					"protocol igmp",
					"action accept",
				)
			}

			tree.AttachFirewallToInterface(nic.Name, "local")
		}
		tree.Apply(false)
	}

	/* generate pimd.conf */
	updatePimdConf(cmd)
	restartPimd()

	pimdEnable = true

	return nil
}

func removePimdFirewallByIptables(nics map[string]utils.Nic)  error{
	for _, nic := range nics {
		utils.DeleteFirewallRuleByComment(nic.Name, utils.PIMDComment + nic.Name)
	}

	return nil
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
		}
		tree.Apply(false)
	}

	stopPimd()

	pimdEnable = false

	return nil
}

func getMrouteHandler(ctx *server.CommandContext) interface{} {
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo ip mroute"),
	}

	_, out, _, _ := bash.RunWithReturn();
	if out == "" {
		return getMrouteRsp{Routes:nil}
	}

	/* line of mroute: (10.86.5.99, 239.1.1.1)          Iif: eth0       Oifs: eth1 pimreg */
	routes := []mRouteInfo{}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		var ingress, egress []string
		src := ""
		group := ""
		in := false
		out := false
		items := strings.Split(line, " ")

		for _, item := range items {
			if item == " " || item == ""{
				continue
			}

			if strings.Contains(item, "(") {
				src = strings.Trim(item, " ")
				src = strings.TrimPrefix(src, "(")
				src = strings.TrimSuffix(src, ",")
				continue
			}

			if strings.Contains(item, ")") {
				group = strings.TrimSuffix(item, ")")
				continue
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
				if item != "pimreg" {
					item = strings.TrimSuffix(item, ",")
					egress = append(egress, item)
				}
			}
		}

		if group == "" {
			continue
		}

		route := mRouteInfo{SourceAddress: src, GroupAddress: group, IngressInterfaces: strings.Join(ingress, " "),
			EgressInterfaces: strings.Join(egress, " ")}
		routes = append(routes, route)
	}

	return getMrouteRsp{Routes:routes}
}

func PimdEntryPoint() {
	server.RegisterAsyncCommandHandler(ENABLE_PIMD_PATH, server.VyosLock(enablePimdHandler))
	server.RegisterAsyncCommandHandler(DISABLE_PIMD_PATH, server.VyosLock(disablePimdHandler))
	server.RegisterAsyncCommandHandler(GET_MROUTE_PATH, getMrouteHandler)
}
