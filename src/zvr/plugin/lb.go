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
	log "github.com/Sirupsen/logrus"
)

const (
	REFRESH_LB_PATH = "/lb/refresh"
	DELETE_LB_PATH = "/lb/delete"
	CREATE_CERTIFICATE_PATH = "/certificate/create"

	LB_ROOT_DIR = "/home/vyos/zvr/lb/"
	LB_CONF_DIR = "/home/vyos/zvr/lb/conf/"
	CERTIFICATE_ROOT_DIR = "/home/vyos/zvr/certificate/"

	LB_MODE_HTTPS = "https"
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
	CertificateUuid string `json:"certificateUuid"`
}

type certificateInfo struct {
	Uuid string `json:"uuid"`
	Certificate string `json:"certificate"`
}

func makeLbPidFilePath(lb lbInfo) string {
	return filepath.Join(LB_ROOT_DIR, "pid", fmt.Sprintf("lb-%s-listener-%s.pid", lb.LbUuid, lb.ListenerUuid))
}

func makeLbConfFilePath(lb lbInfo) string {
	return filepath.Join(LB_ROOT_DIR, "conf", fmt.Sprintf("lb-%v-listener-%v.cfg", lb.LbUuid, lb.ListenerUuid))
}

func makeCertificatePath(certificateUuid string) string {
	return filepath.Join(CERTIFICATE_ROOT_DIR, fmt.Sprintf("certificate-%s.pem", certificateUuid))
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

func conLbudp(m map[string]interface{},lb lbInfo) (retCode int, err error){
	conf := `[logging]
level = "info"   # "debug" | "info" | "warn" | "error"
output = "/var/log/gobetwwen_{{.ListenerUuid}}.log" # "stdout" | "stderr" | "/path/to/gobetween.log"

[servers.{{.ListenerUuid}}]
bind = "{{.Vip}}:{{.LoadBalancerPort}}"
protocol = "{{.Mode}}"
{{if eq .BalancerAlgorithm "source"}}
balance = "iphash"
{{else}}
balance = "{{.BalancerAlgorithm}}"
{{end}}
max_connections = {{.MaxConnection}}
client_idle_timeout = "{{.ConnectionIdleTimeout}}s"
backend_idle_timeout = "{{.ConnectionIdleTimeout}}s"
backend_connection_timeout = "60s"

    [servers.{{.ListenerUuid}}.discovery]
    kind = "static"
    failpolicy = "keeplast"
    static_list = [
	{{ range $index, $ip := .NicIps }}
      "{{$ip}}:{{$.CheckPort}}",
    {{ end }}
    ]

    [servers.{{.ListenerUuid}}.healthcheck]
    fails = {{$.UnhealthyThreshold}}
    passes = {{$.HealthyThreshold}}
    interval = "{{$.HealthCheckInterval}}s"
    timeout="{{$.HealthCheckInterval}}s"
    kind = "exec"
    exec_command = "/usr/share/healthcheck.sh"  # (required) command to execute
    exec_expected_positive_output = "success"           # (required) expected output of command in case of success
    exec_expected_negative_output = "fail"
`

	var buf bytes.Buffer
	tmpl, err := template.New("conf").Parse(conf); utils.PanicOnError(err)
	err = tmpl.Execute(&buf, m); utils.PanicOnError(err)

	pidPath := makeLbPidFilePath(lb)
	err = utils.MkdirForFile(pidPath, 0755); utils.PanicOnError(err)
	confPath := makeLbConfFilePath(lb)
	err = utils.MkdirForFile(confPath, 0755); utils.PanicOnError(err)
	err = ioutil.WriteFile(confPath, buf.Bytes(), 0755); utils.PanicOnError(err)
	bakPath := fmt.Sprintf("%s.md5", confPath)

	pid, err := utils.FindFirstPIDByPS( confPath)
	if pid > 0 {
		log.Debugf("lb %s pid: %v", confPath, pid)
		confbakChecksum := ""
		confChecksum := ""
		if e, _ := utils.PathExists(bakPath); e {

			bash := utils.Bash{
				//Command: fmt.Sprintf("sudo /opt/vyatta/sbin/gobetween -c %s&echo $! >%s", confPath, pidPath),
				Command: fmt.Sprintf("cat %s", bakPath),
			}
			ret, out, _, err := bash.RunWithReturn();bash.PanicIfError()
			if ret != 0 || err != nil {
				return ret, err
			}
			confbakChecksum = out
		}

		bash := utils.Bash{
			//Command: fmt.Sprintf("sudo /opt/vyatta/sbin/gobetween -c %s&echo $! >%s", confPath, pidPath),
			Command: fmt.Sprintf("md5sum %s |awk '{print $1}'", confPath),
		}

		ret, confChecksum, _, err := bash.RunWithReturn();bash.PanicIfError()
		if  ret != 0 || err != nil {
			return ret, err
		}

		log.Debugf("lb %s confChecksum: %v, confbakChecksum: %v", confPath, confChecksum, confbakChecksum)

		if confChecksum != confbakChecksum {
			err := utils.KillProcess(pid); utils.PanicOnError(err)
		} else {
			return 0, nil
		}
	}

	bash := utils.Bash{
		//Command: fmt.Sprintf("sudo /opt/vyatta/sbin/gobetween -c %s&echo $! >%s", confPath, pidPath),
		Command: fmt.Sprintf("sudo /opt/vyatta/sbin/gobetween -c %s >/dev/null 2>&1&echo $! >%s &&  " +
			"md5sum %s |awk '{print $1}' >%s", confPath, pidPath, confPath, bakPath),
	}

	ret, _, _, err := bash.RunWithReturn();bash.PanicIfError()

	return ret, err
}

func conLbtcp(m map[string]interface{},lb lbInfo) (retCode int, err error){
	conf := `global
maxconn {{.MaxConnection}}
log 127.0.0.1 local1
user vyos
group users
daemon

defaults
log global
option tcplog
option dontlognull
option http-server-close

listen {{.ListenerUuid}}
{{if eq .Mode "https"}}
mode http
{{else}}
mode {{.Mode}}
{{end}}
{{if ne .Mode "tcp"}}
option forwardfor
{{end}}
timeout client {{.ConnectionIdleTimeout}}s
timeout server {{.ConnectionIdleTimeout}}s
timeout connect 60s
balance {{.BalancerAlgorithm}}
{{if eq .Mode "https"}}
bind {{.Vip}}:{{.LoadBalancerPort}} ssl crt {{.CertificatePath}}
{{else}}
bind {{.Vip}}:{{.LoadBalancerPort}}
{{end}}
{{ range $index, $ip := .NicIps }}
server nic-{{$ip}} {{$ip}}:{{$.InstancePort}} check port {{$.CheckPort}} inter {{$.HealthCheckInterval}}s rise {{$.HealthyThreshold}} fall {{$.UnhealthyThreshold}}
{{ end }}`

	var buf bytes.Buffer
	tmpl, err := template.New("conf").Parse(conf); utils.PanicOnError(err)
	err = tmpl.Execute(&buf, m); utils.PanicOnError(err)

	pidPath := makeLbPidFilePath(lb)
	err = utils.MkdirForFile(pidPath, 0755); utils.PanicOnError(err)
	confPath := makeLbConfFilePath(lb)
	err = utils.MkdirForFile(confPath, 0755); utils.PanicOnError(err)
	err = ioutil.WriteFile(confPath, buf.Bytes(), 0755); utils.PanicOnError(err)
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo /opt/vyatta/sbin/haproxy -D -N %s -f %s -p %s -sf $(cat %s)", m["MaxConnection"], confPath, pidPath, pidPath),
	}

	ret, _, _, err := bash.RunWithReturn();bash.PanicIfError()

	return ret, err
}

type CON_FUNC func( map[string]interface{}, lbInfo) (int, error)

func setLb(lb lbInfo) {
	//var conFun CON_FUNC
	conFun := conLbtcp
	prot :="tcp"

	if lb.Mode == "udp" {
		prot = "udp"
		conFun = conLbudp
	}
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
	m["CertificatePath"] = makeCertificatePath(lb.CertificateUuid)

	// drop SYN packets to make clients to resend
	// this is for restarting LB without losing packets
	nicname, err := utils.GetNicNameByIp(lb.Vip); utils.PanicOnError(err)
	tree := server.NewParserFromShowConfiguration().Tree
	dropRuleDes := fmt.Sprintf("lb-%v-%s-drop", lb.LbUuid, lb.ListenerUuid)
	if prot =="tcp" {
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
	}
	des := makeLbFirewallRuleDescription(lb)
	if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %v", des),
			fmt.Sprintf("destination address %v", lb.Vip),
			fmt.Sprintf("destination port %v", lb.LoadBalancerPort),
			fmt.Sprintf("protocol %v",prot),
			"action accept",
		)
	}

	tree.AttachFirewallToInterface(nicname, "local")
	tree.Apply(false)

	defer func() {
		// delete the DROP SYNC rule on exit
		if prot =="tcp" {
			tree := server.NewParserFromShowConfiguration().Tree
			if r := tree.FindFirewallRuleByDescription(nicname, "local", dropRuleDes); r != nil {
				r.Delete()
			}
			tree.Apply(false)
		}
	}()

	time.Sleep(time.Duration(1) * time.Second)
	if  ret,err := conFun(m, lb); ret != 0 || err != nil {
		// fail, cleanup the firewall rule
		tree = server.NewParserFromShowConfiguration().Tree
		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r != nil {
			r.Delete()
		}
		tree.Apply(false)
	}
}

func getCertificateList() []string {
	bash := utils.Bash{
		Command: fmt.Sprintf("find %s -name '*.pem'", CERTIFICATE_ROOT_DIR),
	}

	if ret, res, _, err := bash.RunWithReturn(); ret != 0 || err != nil {
		return nil
	} else {
		return strings.Split(res, "\n")
	}
}

func isCertificateUsed(certificateFile string) bool {
	bash := utils.Bash{
		Command: fmt.Sprintf("grep -r %s %s", certificateFile, LB_CONF_DIR),
	}

	if ret, res, _, err := bash.RunWithReturn(); ret != 0 || err != nil {
		return false
	} else if res == ""{
		return false
	} else {
		return true
	}
}

func remoteUsedCertificate()  {
	files := getCertificateList()
	for _, file := range files {
		if file != "" && !isCertificateUsed(file) {
			err := os.Remove(file); utils.LogError(err)
		}
	}
}

func refreshLb(ctx *server.CommandContext) interface{} {
	cmd := &refreshLbCmd{}
	ctx.GetCommand(cmd)

	for _, lb := range cmd.Lbs {
		if len(lb.NicIps) == 0 {
			delLb(lb)
		} else if (lb.Mode == LB_MODE_HTTPS && lb.CertificateUuid == "") {
			delLb(lb)
		} else {
			setLb(lb)
		}
	}

	remoteUsedCertificate()

	return nil
}

func delLb(lb lbInfo) {
	pidPath := makeLbPidFilePath(lb)
	confPath := makeLbConfFilePath(lb)

	//miao zhanyong the udp lb configured by gobetween, there is no pid configure in the shell cmd line
	pid, err := utils.FindFirstPIDByPS( confPath)
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
		for _, lb := range cmd.Lbs {
			delLb(lb)
		}
	}

	remoteUsedCertificate()

	return nil
}

func createCertificate(ctx *server.CommandContext) interface{} {
	certificate := &certificateInfo{}
	ctx.GetCommand(certificate)

	certificatePath := makeCertificatePath(certificate.Uuid)
	if e, _ := utils.PathExists(certificatePath); e {
		/* certificate create api may be called multiple times */
		return nil
	}

	err := utils.MkdirForFile(certificatePath, 0755); utils.PanicOnError(err)
	err = ioutil.WriteFile(certificatePath, []byte(certificate.Certificate), 0755); utils.PanicOnError(err)

	return nil
}

func LbEntryPoint() {
	server.RegisterAsyncCommandHandler(REFRESH_LB_PATH, server.VyosLock(refreshLb))
	server.RegisterAsyncCommandHandler(DELETE_LB_PATH, server.VyosLock(deleteLb))
	server.RegisterAsyncCommandHandler(CREATE_CERTIFICATE_PATH, server.VyosLock(createCertificate))
}
