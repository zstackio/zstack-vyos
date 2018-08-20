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
	//"time"
	"os"
	"sort"
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

type Listener interface {
	createListenerServiceConfigure(lb lbInfo)  ( err error)
	checkIfListenerServiceUpdate(origChecksum string, currChecksum string) ( bool, error)
	preActionListenerServiceStart() ( err error)
	rollbackPreActionListenerServiceStart() ( err error)
	startListenerService() (ret int, err error)
	postActionListenerServiceStart() ( err error)
	preActionListenerServiceStop() (ret int, err error)
	stopListenerService() ( err error)
	postActionListenerServiceStop() (ret int, err error)
}

// the listener implemented with HaProxy
type HaproxyListener struct {
	lb lbInfo
	confPath string
	pidPath	string
	firewallDes string
	maxConnect string
}

// the listener implemented with gobetween
type GBListener struct {
	lb lbInfo
	confPath string
	pidPath	string
	firewallDes string
}

func GetListener(lb lbInfo) Listener {
	pidPath := makeLbPidFilePath(lb)
	confPath := makeLbConfFilePath(lb)
	des := makeLbFirewallRuleDescription(lb)

	switch lb.Mode {
	case "udp":
		return &GBListener{lb:lb, confPath: confPath, pidPath:pidPath,  firewallDes:des}
	case "tcp", "https", "http":
		return &HaproxyListener{lb:lb, confPath: confPath, pidPath:pidPath, firewallDes:des}
	default:
		panic(fmt.Sprintf("No such listener %v", lb.Mode))
	}
	return nil
}

func parseListenerPrameter(lb lbInfo) (map[string]interface{}, error) {
	sort.Stable(sort.StringSlice(lb.NicIps))
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

	return m, nil
}


func (this *HaproxyListener) createListenerServiceConfigure(lb lbInfo)  (err error) {
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
	var m map[string]interface{}

	tmpl, err := template.New("conf").Parse(conf); utils.PanicOnError(err)
	m, err = parseListenerPrameter(lb);utils.PanicOnError(err)

	err = tmpl.Execute(&buf, m); utils.PanicOnError(err)
	this.maxConnect = m["MaxConnection"].(string)
	err = utils.MkdirForFile(this.pidPath, 0755); utils.PanicOnError(err)
	err = utils.MkdirForFile(this.confPath, 0755); utils.PanicOnError(err)
	err = ioutil.WriteFile(this.confPath, buf.Bytes(), 0755); utils.PanicOnError(err)
	return err
}

func (this *HaproxyListener) startListenerService() ( ret int, err error) {
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo /opt/vyatta/sbin/haproxy -D -N %s -f %s -p %s -sf $(cat %s)",
			this.maxConnect, this.confPath, this.pidPath, this.pidPath),
	}

	ret, _, _, err = bash.RunWithReturn(); bash.PanicIfError()
	return ret, err
}


func (this *HaproxyListener) checkIfListenerServiceUpdate(origChecksum string, currChecksum string) ( bool, error) {
	pid, err := utils.FindFirstPIDByPS( this.confPath, this.pidPath)
	if pid > 0 {
		log.Debugf("lb %s pid: %v orig: %v curr: %v", this.confPath, pid, origChecksum, currChecksum)
		return strings.EqualFold(origChecksum, currChecksum) == false, nil
	} else if (pid == -1) {
		err = nil
	}
	return true, err
}

func (this *HaproxyListener) preActionListenerServiceStart() ( err error) {
	// drop SYN packets to make clients to resend, this is for restarting LB without losing packets
	nicname, err := utils.GetNicNameByIp(this.lb.Vip ); utils.PanicOnError(err)
	tree := server.NewParserFromShowConfiguration().Tree

	dropRuleDes := fmt.Sprintf("lb-%v-%s-drop", this.lb.LbUuid, this.lb.ListenerUuid)
	if r := tree.FindFirewallRuleByDescription(nicname, "local", dropRuleDes); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %v", dropRuleDes),
			fmt.Sprintf("destination address %v", this.lb.Vip),
			fmt.Sprintf("destination port %v", this.lb.LoadBalancerPort),
			"protocol tcp",
			"tcp flags SYN",
			"action drop",
		)
		tree.AttachFirewallToInterface(nicname, "local")
		tree.Apply(false)
	}

	return nil
}

func (this *HaproxyListener) rollbackPreActionListenerServiceStart() ( err error) {
	// drop SYN packets to make clients to resend, this is for restarting LB without losing packets
	nicname, err := utils.GetNicNameByIp(this.lb.Vip ); utils.PanicOnError(err)
	tree := server.NewParserFromShowConfiguration().Tree

	dropRuleDes := fmt.Sprintf("lb-%v-%s-drop", this.lb.LbUuid, this.lb.ListenerUuid)
	if r := tree.FindFirewallRuleByDescription(nicname, "local", dropRuleDes); r != nil {
		r.Delete()
		tree.Apply(false)
	}

	return nil
}

func (this *HaproxyListener) postActionListenerServiceStart() ( err error) {
	nicname, err := utils.GetNicNameByIp(this.lb.Vip ); utils.PanicOnError(err)
	tree := server.NewParserFromShowConfiguration().Tree

	if r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallDes); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %v", this.firewallDes),
			fmt.Sprintf("destination address %v", this.lb.Vip),
			fmt.Sprintf("destination port %v", this.lb.LoadBalancerPort),
			fmt.Sprintf("protocol tcp"),
			"action accept",
		)

	}
	dropRuleDes := fmt.Sprintf("lb-%v-%s-drop", this.lb.LbUuid, this.lb.ListenerUuid)
	if r := tree.FindFirewallRuleByDescription(nicname, "local", dropRuleDes); r != nil {
		r.Delete()
	}

	tree.AttachFirewallToInterface(nicname, "local")
	tree.Apply(false)

	return nil
}





func (this *HaproxyListener) preActionListenerServiceStop() (ret int, err error) {
	return 0, nil
}

func (this *HaproxyListener) stopListenerService() ( err error) {
	//miao zhanyong the udp lb configured by gobetween, there is no pid configure in the shell cmd line
	pid, err := utils.FindFirstPIDByPS(this.confPath, this.pidPath)
	log.Debugf("lb %s pid: %v result:%v", this.confPath, pid, err)
	if pid > 0 {
		err = utils.KillProcess(pid); utils.PanicOnError(err)
	} else if (pid == -1) {
		err = nil
	}
	return err
}

func (this *HaproxyListener) postActionListenerServiceStop() (ret int, err error) {
	nicname, err := utils.GetNicNameByIp(this.lb.Vip); utils.PanicOnError(err)
	tree := server.NewParserFromShowConfiguration().Tree
	if r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallDes); r != nil {
		r.Delete()
	}
	tree.Apply(false)

	if e, _ := utils.PathExists(this.pidPath); e {
		err = os.Remove(this.pidPath); utils.LogError(err)
	}
	if e, _ := utils.PathExists(this.confPath); e {
		err = os.Remove(this.confPath); utils.LogError(err)
	}

	return 0, err
}


func (this *GBListener) createListenerServiceConfigure(lb lbInfo)  (err error) {
		conf := `[logging]
level = "info"   # "debug" | "info" | "warn" | "error"
output = "./zvr/lb/gobetwwen_{{.ListenerUuid}}.log" # "stdout" | "stderr" | "/path/to/gobetween.log"

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
	var m map[string]interface{}

	tmpl, err := template.New("conf").Parse(conf); utils.PanicOnError(err)
	m, err = parseListenerPrameter(lb);utils.PanicOnError(err)

	err = tmpl.Execute(&buf, m); utils.PanicOnError(err)
	err = utils.MkdirForFile(this.pidPath, 0755); utils.PanicOnError(err)
	err = utils.MkdirForFile(this.confPath, 0755); utils.PanicOnError(err)
	err = ioutil.WriteFile(this.confPath, buf.Bytes(), 0755); utils.PanicOnError(err)
	return err
}

func (this *GBListener) startListenerService() ( ret int, err error) {
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo /opt/vyatta/sbin/gobetween -c %s >/dev/null 2>&1&echo $! >%s",
			this.confPath, this.pidPath),
	}

	ret, _, _, err = bash.RunWithReturn(); bash.PanicIfError()
	return ret, err
}

/*get the md5 vaule of a file, return null string if the file not exist */
func getFileChecksum(file string) (checksum string, err error) {
	checksum = ""
	if e, _ := utils.PathExists(file); e {

		bash := utils.Bash{
			Command: fmt.Sprintf("md5sum %s |awk '{print $1}'", file),
		}
		ret, out, _, err := bash.RunWithReturn();bash.PanicIfError()
		if ret != 0 || err != nil {
			return "", err
		}
		checksum = out
	}

	return checksum, nil
}

func (this *GBListener) checkIfListenerServiceUpdate(origChecksum string, currChecksum string) ( bool, error) {
	pid, _:= utils.FindFirstPIDByPS( this.confPath)
	if pid > 0 {
		log.Debugf("lb %s pid: %v orig: %v curr: %v", this.confPath, pid, origChecksum, currChecksum)
		if strings.EqualFold(origChecksum, currChecksum) == false {
			err := utils.KillProcess(pid); utils.PanicOnError(err)
			return true, err
		}
		return false, nil
	}
	return true, nil
}

func (this *GBListener) preActionListenerServiceStart() ( err error) {
	return nil
}
func (this *GBListener) rollbackPreActionListenerServiceStart() ( err error) {
	return nil
}
func (this *GBListener) postActionListenerServiceStart() ( err error) {
	// drop SYN packets to make clients to resend, this is for restarting LB without losing packets
	nicname, err := utils.GetNicNameByIp(this.lb.Vip ); utils.PanicOnError(err)
	tree := server.NewParserFromShowConfiguration().Tree

	if r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallDes); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %v", this.firewallDes),
			fmt.Sprintf("destination address %v", this.lb.Vip),
			fmt.Sprintf("destination port %v", this.lb.LoadBalancerPort),
			fmt.Sprintf("protocol udp"),
			"action accept",
		)
		tree.AttachFirewallToInterface(nicname, "local")
		tree.Apply(false)
	}

	return nil
}


func (this *GBListener) preActionListenerServiceStop() (ret int, err error) {
	return 0, nil
}

func (this *GBListener) stopListenerService() ( err error) {
	//miao zhanyong the udp lb configured by gobetween, there is no pid configure in the shell cmd line
	pid, err := utils.FindFirstPIDByPS(this.confPath)
	log.Debugf("lb %s pid: %v result:%v", this.confPath, pid, err)
	err = nil
	if pid > 0 {
		err = utils.KillProcess(pid); utils.PanicOnError(err)
	} else if (pid == -1) {
		err = nil
	}

	return err
}

func (this *GBListener) postActionListenerServiceStop() (ret int, err error) {
	nicname, err := utils.GetNicNameByIp(this.lb.Vip); utils.PanicOnError(err)
	tree := server.NewParserFromShowConfiguration().Tree
	if r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallDes); r != nil {
		r.Delete()
	}
	tree.Apply(false)

	if e, _ := utils.PathExists(this.pidPath); e {
		err = os.Remove(this.pidPath); utils.LogError(err)
	}
	if e, _ := utils.PathExists(this.confPath); e {
		err = os.Remove(this.confPath); utils.LogError(err)
	}

	logPath := fmt.Sprintf("./zvr/lb/gobetwwen_%s.log", this.lb.ListenerUuid)
	if e, _ := utils.PathExists(logPath); e {
		err = os.Remove(logPath); utils.LogError(err)
	}

	return 0, err
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

func setLb(lb lbInfo) {
	listener := GetListener(lb)
	if  listener == nil {
		return
	}

	checksum, err := getFileChecksum(makeLbConfFilePath(lb))
	if err != nil {
		log.Errorf("get listener checksum fail %v \n", lb.ListenerUuid)
		return
	}

	err = listener.createListenerServiceConfigure(lb); utils.PanicOnError(err)
	newChecksum, err1 := getFileChecksum(makeLbConfFilePath(lb)); utils.PanicOnError(err1)
	if update, err := listener.checkIfListenerServiceUpdate(checksum, newChecksum); err == nil && !update {
		log.Debugf("no need refresh the listener: %v\n", lb.ListenerUuid)
		return
	}
	utils.PanicOnError(err)

	err = listener.preActionListenerServiceStart(); utils.PanicOnError(err)
	//time.Sleep(time.Duration(1) * time.Second)
	if ret, err := listener.startListenerService(); ret != 0 || err != nil {
		log.Errorf("start listener fail %v \n", lb.ListenerUuid)
		listener.rollbackPreActionListenerServiceStart()
		return
	}

	if err := listener.postActionListenerServiceStart(); err != nil {
		utils.PanicOnError(err);
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
	listener := GetListener(lb)
	if  listener == nil {
		return
	}
	_, err := listener.preActionListenerServiceStop(); utils.PanicOnError(err)
	err = listener.stopListenerService(); utils.PanicOnError(err)
	_, err = listener.postActionListenerServiceStop(); utils.PanicOnError(err)
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
