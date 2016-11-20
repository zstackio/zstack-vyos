package plugin

import (
	"zvr/server"
	"html/template"
	"zvr/utils"
	"bytes"
	"github.com/fatih/structs"
	"strings"
	"fmt"
	"path/filepath"
	"io/ioutil"
	"time"
	"os"
	//log "github.com/Sirupsen/logrus"
)

const (
	REFRESH_LB_PATH = "/lb/refresh"
	DELETE_LB_PATH = "/lb/delete"

	LB_ROOT_DIR = "/home/vyos/zvr/lb/"
)

type lbInfo struct {
	LbUuid string `json:"lbUuid"`
	ListenerUuid string `json:"listenerUuid"`
	Vip string `json:"vip"`
	NicIps []string `json:"nicIps"`
	InstancePort int `json:"instancePort"`
	LoadBalancerPort int `json:"loadBalancerPort"`
	Mode string `json:"mode"`
	Parameters []string `json:"parameters"`
}

func makeLbPidFilePath(lb lbInfo) string {
	return filepath.Join(LB_ROOT_DIR, "pid", fmt.Sprintf("lb-%v-listener-%v.pid", lb.LbUuid, lb.ListenerUuid))
}

func makeLbConfFilePath(lb lbInfo) string {
	return filepath.Join(LB_ROOT_DIR, "conf", fmt.Sprintf("lb-%v-listener-%v.cfg", lb.LbUuid, lb.ListenerUuid))
}

type refreshLbCmd struct {
	Lbs []lbInfo `json:"lbs"`
}

type deleteLbCmd struct {
	Lbs []lbInfo `json:"lbs"`
}

func makeLbFirewallRuleDescription(lb lbInfo) string {
	return fmt.Sprintf("LB-%v-%v", lb.LbUuid, lb.ListenerUuid)
}

func setLb(lb lbInfo) {
	conf := `global
maxconn {{.MaxConnection}}
log 127.0.0.1 local1
user vyos
group users
daemon

listen {{.ListenerUuid}}
mode {{.Mode}}
timeout client {{.ConnectionIdleTimeout}}s
timeout server {{.ConnectionIdleTimeout}}s
timeout connect 60s
balance {{.BalancerAlgorithm}}
bind {{.Vip}}:{{.LoadBalancerPort}}
{{ range $index, $ip := .NicIps }}
server nic-{{$ip}} {{$ip}}:{{$.InstancePort}} check port {{$.CheckPort}} inter {{$.HealthCheckInterval}}s rise {{$.HealthyThreshold}} fall {{$.UnhealthyThreshold}}
{{ end }}`

	tmpl, err := template.New("conf").Parse(conf); utils.PanicOnError(err)
	var buf bytes.Buffer
	m := structs.Map(lb)
	for _, param := range lb.Parameters {
		kv := strings.SplitN(param, "::", 2)
		k := kv[0]
		v := kv[1]

		if k == "healthCheckTarget" {
			mp := strings.Split(v, ":")
			cport := mp[1]
			if cport == "default" {
				m["CheckPort"] = lb.InstancePort
			} else {
				m["CheckPort"] = cport
			}
		} else {
			m[strings.Title(k)] = v
		}
	}

	err = tmpl.Execute(&buf, m); utils.PanicOnError(err)

	pidPath := makeLbPidFilePath(lb)
	err = utils.MkdirForFile(pidPath, 0755); utils.PanicOnError(err)
	confPath := makeLbConfFilePath(lb)
	err = utils.MkdirForFile(confPath, 0755); utils.PanicOnError(err)
	err = ioutil.WriteFile(confPath, buf.Bytes(), 0755); utils.PanicOnError(err)

	// drop SYN packets to make clients to resend
	// this is for restarting LB without losing packets
	nicname, err := utils.GetNicNameByIp(lb.Vip); utils.PanicOnError(err)
	tree := server.NewParserFromShowConfiguration().Tree
	dropRuleDes := fmt.Sprintf("lb-%v-%s-drop", lb.LbUuid, lb.ListenerUuid)
	if r := tree.FindFirewallRuleByDescription(nicname, "local", dropRuleDes); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %v", dropRuleDes),
			fmt.Sprintf("destination address %v", lb.Vip),
			fmt.Sprintf("destination port %v", lb.LoadBalancerPort),
			"protocol tcp",
			"tcp flags SYN",
			"action drop",
		)
	}

	des := makeLbFirewallRuleDescription(lb)
	if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %v", des),
			fmt.Sprintf("destination address %v", lb.Vip),
			fmt.Sprintf("destination port %v", lb.LoadBalancerPort),
			"protocol tcp",
			"action accept",
		)
	}

	tree.AttachFirewallToInterface(nicname, "local")
	tree.Apply(false)

	defer func() {
		// delete the DROP SYNC rule on exit
		tree := server.NewParserFromShowConfiguration().Tree
		if r := tree.FindFirewallRuleByDescription(nicname, "local", dropRuleDes); r != nil {
			r.Delete()
		}
		tree.Apply(false)
	}()

	time.Sleep(time.Duration(1) * time.Second)

	bash := utils.Bash{
		Command: fmt.Sprintf("sudo /opt/vyatta/sbin/haproxy -D -f %s -p %s -sf $(cat %s)", confPath, pidPath, pidPath),
	}

	if ret, _, _, err := bash.RunWithReturn(); ret != 0 || err != nil {
		// fail, cleanup the firewall rule
		tree = server.NewParserFromShowConfiguration().Tree
		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r != nil {
			r.Delete()
		}
		tree.Apply(false)
	}

	bash.PanicIfError()
}

func refreshLb(ctx *server.CommandContext) interface{} {
	cmd := &refreshLbCmd{}
	ctx.GetCommand(cmd)

	for _, lb := range cmd.Lbs {
		if len(lb.NicIps) == 0 {
			delLb(lb)
		} else {
			setLb(lb)
		}
	}

	return nil
}

func delLb(lb lbInfo) {
	pidPath := makeLbPidFilePath(lb)
	confPath := makeLbConfFilePath(lb)

	pid, err := utils.FindPIDByPS(pidPath, confPath)
	if pid > 0 {
		err := utils.KillProcess(pid); utils.PanicOnError(err)
	}

	nicname, err := utils.GetNicNameByIp(lb.Vip); utils.PanicOnError(err)
	des := makeLbFirewallRuleDescription(lb)
	tree := server.NewParserFromShowConfiguration().Tree
	if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r != nil {
		r.Delete()
	}
	tree.Apply(false)

	if e, _ := utils.PathExists(pidPath); e {
		err = os.Remove(pidPath); utils.LogError(err)
	}
	if e, _ := utils.PathExists(confPath); e {
		err = os.Remove(confPath); utils.LogError(err)
	}
}

func deleteLb(ctx *server.CommandContext) interface{} {
	cmd := &deleteLbCmd{}
	ctx.GetCommand(cmd)

	if len(cmd.Lbs) > 0 {
		delLb(cmd.Lbs[0])
	}

	return nil
}

func LbEntryPoint() {
	server.RegisterAsyncCommandHandler(REFRESH_LB_PATH, server.VyosLock(refreshLb))
	server.RegisterAsyncCommandHandler(DELETE_LB_PATH, server.VyosLock(deleteLb))
}
