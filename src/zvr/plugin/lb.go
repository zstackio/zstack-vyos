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
	"strconv"
	"os"
	"regexp"
	prom "github.com/prometheus/client_golang/prometheus"
	haproxy "github.com/bcicen/go-haproxy"
	"sort"
	log "github.com/Sirupsen/logrus"
	"net/http"
	"time"
	"encoding/json"
	"errors"
)

const (
	REFRESH_LB_PATH = "/lb/refresh"
	DELETE_LB_PATH = "/lb/delete"
	CREATE_CERTIFICATE_PATH = "/certificate/create"

	LB_ROOT_DIR = "/home/vyos/zvr/lb/"
	LB_CONF_DIR = "/home/vyos/zvr/lb/conf/"
	CERTIFICATE_ROOT_DIR = "/home/vyos/zvr/certificate/"
	LB_SOCKET_DIR = "/home/vyos/zvr/lb/sock/"

	LB_MODE_HTTPS = "https"

	LB_BACKEND_PREFIX_REG = "^nic-"

	LISTENER_MAP_SIZE = 128
	//reserve some sockets for haproxy if specify the parameter "ulimit-n"
	RESERVE_SOCK_COUNT = 100
	MAX_SOCK_COUNT = 1048576
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
        getGoBetweenCounters(listenerUuid string) ([]*LbCounter, int)
}

// the listener implemented with HaProxy
type HaproxyListener struct {
	lb lbInfo
	confPath string
	pidPath	string
	sockPath string
	firewallDes string
	maxConnect string
}

// the listener implemented with gobetween
type GBListener struct {
	lb lbInfo
	confPath string
	pidPath	string
	firewallDes string
	apiPort string // restapi binding port range from 50000-60000
}

func getGBApiPort(confPath string, pidPath string) (port string) {
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo /bin/netstat -tnlp"),
	}

	if ret, out, _, err := bash.RunWithReturn(); ret != 0 || err != nil {
		bash.PanicIfError()
	} else {
		port =""
		pid, _ := utils.FindFirstPIDByPSExtern(true, confPath)
		if pid > 0 {
			//get current port used
			kv := strings.SplitN(out, "\n", -1)
			for start := 50000; start < 60000; start++ {
				port = strconv.Itoa(start)
				//find the record ":port * pid/gobetween"
				if strings.Contains(out, ":" + port) {
					for _, str := range kv {
						if strings.Contains(str, ":" + port) && strings.Contains(str, strconv.Itoa(pid) + "/gobetween") {
							//log.Debugf("lb %s pid: %v api port: %v ", confPath, pid, port)
							return port
						}
					}
				}

			}
			//log.Debugf("%v port&%d not found in \n %v\n", pidPath, pid, out)
		}

		for start := 50000; start < 60000; start++ {
			if !strings.Contains(out, ":" + strconv.Itoa(start)) {
				port = strconv.Itoa(start)
				log.Debugf("lb %s pid: %v api port: %v ", confPath, pid, port)
				break
			}
		}

	}

	return port
}

func getListener(lb lbInfo) Listener {
	pidPath := makeLbPidFilePath(lb)
	confPath := makeLbConfFilePath(lb)
	sockPath := makeLbSocketPath(lb)
	des := makeLbFirewallRuleDescription(lb)

	switch lb.Mode {
	case "udp":
		port := getGBApiPort(confPath, pidPath)
		if port == "" {
			log.Errorf("there is no free port for rest api for listener: %v \n", lb.ListenerUuid)
			return nil
		}
		return &GBListener{lb:lb, confPath: confPath, pidPath:pidPath, firewallDes:des, apiPort:port}
	case "tcp", "https", "http":
		return &HaproxyListener{lb:lb, confPath: confPath, pidPath:pidPath, firewallDes:des, sockPath:sockPath}
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
	m["SocketPath"] = makeLbSocketPath(lb)
	return m, nil
}

func getListenerMaxCocurrenceSocket(maxConnect string) (string) {
	maxSocket, err := strconv.Atoi(maxConnect); utils.PanicOnError(err)
	maxSocket = maxSocket*2 + RESERVE_SOCK_COUNT

	if maxSocket > MAX_SOCK_COUNT {
		log.Errorf("invalid prameter maxconn %v,please check it", maxConnect)
		maxSocket = MAX_SOCK_COUNT
	}
	return strconv.Itoa(maxSocket)
}

func (this *HaproxyListener) createListenerServiceConfigure(lb lbInfo)  (err error) {
	conf := `global
maxconn {{.MaxConnection}}
log 127.0.0.1 local1
user vyos
group users
daemon
stats socket {{.SocketPath}} user vyos
ulimit-n {{.ulimit}}

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
	this.maxConnect = m["MaxConnection"].(string)

	m["ulimit"] = getListenerMaxCocurrenceSocket(this.maxConnect)

	err = tmpl.Execute(&buf, m); utils.PanicOnError(err)

	err = utils.MkdirForFile(this.pidPath, 0755); utils.PanicOnError(err)
	err = utils.MkdirForFile(this.confPath, 0755); utils.PanicOnError(err)
	err = ioutil.WriteFile(this.confPath, buf.Bytes(), 0755); utils.PanicOnError(err)
	LbListeners[this.lb.ListenerUuid] = this
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
		//log.Debugf("lb %s pid: %v orig: %v curr: %v", this.confPath, pid, origChecksum, currChecksum)
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
	//log.Debugf("lb %s pid: %v result:%v", this.confPath, pid, err)
	if pid > 0 {
		err = utils.KillProcess(pid); utils.PanicOnError(err)
	} else if (pid == -1) {
		err = nil
	}
	utils.CleanConnTrackConnection(this.lb.Vip, "tcp", this.lb.LoadBalancerPort)
	return err
}

func (this *HaproxyListener) postActionListenerServiceStop() (ret int, err error) {
	delete(LbListeners, this.lb.ListenerUuid)

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
	if e, _ := utils.PathExists(this.sockPath); e {
		err = os.Remove(this.sockPath); utils.LogError(err)
	}

	return 0, err
}


func (this *GBListener) createListenerServiceConfigure(lb lbInfo)  (err error) {
		conf := `[api]
enabled = true  # true | false
bind = ":{{.ApiPort}}"  # bind host:port
[logging]
level = "debug"   # "debug" | "info" | "warn" | "error"
#output = "/var/log/gobetween_{{.ListenerUuid}}.log" # "stdout" | "stderr" | "/path/to/gobetween.log"
output = "/var/log/gobetween.log"

[servers.{{.ListenerUuid}}]
bind = "{{.Vip}}:{{.LoadBalancerPort}}"
protocol = "{{.Mode}}"
{{if eq .BalancerAlgorithm "source"}}
balance = "iphash1"
{{else}}
balance = "{{.BalancerAlgorithm}}"
{{end}}
max_connections = {{.MaxConnection}}
client_idle_timeout = "{{.ConnectionIdleTimeout}}s"
backend_idle_timeout = "{{.ConnectionIdleTimeout}}s"
backend_connection_timeout = "60s"
[servers.{{.ListenerUuid}}.udp] # (optional)
max_requests  = 0     # (optional) if > 0 accepts no more requests than max_requests and closes session (since 0.5.0)
max_responses = 0    # (required) if > 0 accepts no more responses that max_responses from backend and closes session (will be optional since 0.5.0)


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
	m["ApiPort"] = this.apiPort
	//m["ulimit"] = getListenerMaxCocurrenceSocket(m["MaxConnection"].(string))

	err = tmpl.Execute(&buf, m); utils.PanicOnError(err)
	err = utils.MkdirForFile(this.pidPath, 0755); utils.PanicOnError(err)
	err = utils.MkdirForFile(this.confPath, 0755); utils.PanicOnError(err)
	err = ioutil.WriteFile(this.confPath, buf.Bytes(), 0755); utils.PanicOnError(err)
	LbListeners[this.lb.ListenerUuid] = this
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
	nicname, err := utils.GetNicNameByIp(this.lb.Vip ); utils.PanicOnError(err)
	tree := server.NewParserFromShowConfiguration().Tree

	if r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallDes); r == nil {
		/*for lb statistics with restful api*/
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %v", this.firewallDes),
			//fmt.Sprintf("destination address %v", this.lb.Vip),
			fmt.Sprintf("destination port %v", this.apiPort),
			fmt.Sprintf("protocol tcp"),
			"action accept",
		)

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
	//log.Debugf("lb %s pid: %v result:%v", this.confPath, pid, err)
	err = nil
	if pid > 0 {
		err = utils.KillProcess(pid); utils.PanicOnError(err)
	} else if (pid == -1) {
		err = nil
	}

	return err
}

func (this *GBListener) postActionListenerServiceStop() (ret int, err error) {
	delete(LbListeners, this.lb.ListenerUuid)

	nicname, err := utils.GetNicNameByIp(this.lb.Vip); utils.PanicOnError(err)
	tree := server.NewParserFromShowConfiguration().Tree
	r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallDes)
	for r != nil{
		r.Delete()
		r = tree.FindFirewallRuleByDescription(nicname, "local", this.firewallDes)
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


func makeLbPidFilePath(lb lbInfo) string {
	return filepath.Join(LB_ROOT_DIR, "pid", fmt.Sprintf("lb-%s-listener-%s.pid", lb.LbUuid, lb.ListenerUuid))
}

func makeLbConfFilePath(lb lbInfo) string {
	return filepath.Join(LB_ROOT_DIR, "conf", fmt.Sprintf("lb-%v-listener-%v.cfg", lb.LbUuid, lb.ListenerUuid))
}

func makeCertificatePath(certificateUuid string) string {
	return filepath.Join(CERTIFICATE_ROOT_DIR, fmt.Sprintf("certificate-%s.pem", certificateUuid))
}

func makeLbSocketPath(lb lbInfo) string {
	return filepath.Join(LB_SOCKET_DIR, fmt.Sprintf("%s.sock", lb.ListenerUuid))
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
	listener := getListener(lb)
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
		//log.Debugf("no need refresh the listener: %v\n", lb.ListenerUuid)
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
	listener := getListener(lb)
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

func init() {
	os.Mkdir(LB_ROOT_DIR, os.ModePerm)
	os.Mkdir(LB_CONF_DIR, os.ModePerm)
	os.Mkdir(LB_SOCKET_DIR, os.ModePerm | os.ModeSocket)
	LbListeners = make(map[string]interface{}, LISTENER_MAP_SIZE)
	enableLbLog()
	RegisterPrometheusCollector(NewLbPrometheusCollector())
}

type loadBalancerCollector struct {
	statusEntry *prom.Desc
	inByteEntry *prom.Desc
	outByteEntry *prom.Desc
	curSessionNumEntry *prom.Desc
}

const (
	LB_LISTENER_UUID = "ListenerUuid"
	LB_LISTENER_BACKEND_IP = "NicIpAddress"
)

func NewLbPrometheusCollector() MetricCollector {
	return &loadBalancerCollector{
		statusEntry: prom.NewDesc(
			"zstack_lb_status",
			"Backend server health status",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP}, nil,
		),
		curSessionNumEntry: prom.NewDesc(
			"zstack_lb_cur_session_num",
			"Backend server active session number",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP}, nil,
		),
		inByteEntry: prom.NewDesc(
			"zstack_lb_in_bytes",
			"Backend server traffic in bytes",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP}, nil,
		),
		outByteEntry: prom.NewDesc(
			"zstack_lb_out_bytes",
			"Backend server traffic in bytes",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP}, nil,
		),

		//vipUUIds: make(map[string]string),
	}
}

func (c *loadBalancerCollector) Describe(ch chan<- *prom.Desc) error {
	ch <- c.statusEntry
	ch <- c.curSessionNumEntry
	ch <- c.inByteEntry
	ch <- c.outByteEntry
	return nil
}

func (c *loadBalancerCollector) Update(ch chan<- prom.Metric) error {
	for listenerUuid, listener := range LbListeners {
		var counters []*LbCounter
		num := 0

		switch listener.(type) {
		case *GBListener:
			gbListener, _ := listener.(*GBListener)
			counters, num = gbListener.getGoBetweenCounters(listenerUuid)
			break
		case *HaproxyListener:
			haproxyListener, _ := listener.(*HaproxyListener)
			counters, num = haproxyListener.getGoBetweenCounters(listenerUuid)
			break
		default:
			log.Infof("can not assert listerner[uuid %s] type", listenerUuid)
			break
		}

		for i := 0; i < num; i++ {
			cnt := counters[i]
			ch <- prom.MustNewConstMetric(c.statusEntry, prom.GaugeValue, float64(cnt.status), cnt.listenerUuid, cnt.ip)
			ch <- prom.MustNewConstMetric(c.inByteEntry, prom.GaugeValue, float64(cnt.bytesIn), cnt.listenerUuid, cnt.ip)
			ch <- prom.MustNewConstMetric(c.outByteEntry, prom.GaugeValue, float64(cnt.bytesOut), cnt.listenerUuid, cnt.ip)
			ch <- prom.MustNewConstMetric(c.curSessionNumEntry, prom.GaugeValue, float64(cnt.sessionNumber), cnt.listenerUuid, cnt.ip)
		}
	}

	return nil
}

type LbCounter struct {
	listenerUuid    string
	ip              string
	status          uint64
	bytesIn         uint64
	bytesOut        uint64
	sessionNumber   uint64
}

func getIpFromLbStat(name string)  string {
	res := strings.Split(name, "-")
	return res[1]
}

func statusFormat(status string) int  {
	switch status {
	case "UP":
		return 1
	/*case "DOWN":
		return 0*/
	default:
		return 0
	}
}

func (this *HaproxyListener) getGoBetweenCounters(listenerUuid string) ([]*LbCounter, int) {
	var counters []*LbCounter
	num := 0

	client := &haproxy.HAProxyClient{
		Addr: "unix://" + this.sockPath,
		Timeout: 5,
	}

	stats, err := client.Stats()
	if (err != nil) {
		log.Infof("client.Stats failed %v", err)
		return nil, 0
	}

	for _, stat := range stats {
		if m, err := regexp.MatchString(LB_BACKEND_PREFIX_REG, stat.SvName); err != nil || !m  {
			continue
		}

		counter := LbCounter{}
		counter.listenerUuid = listenerUuid
		counter.ip = getIpFromLbStat(stat.SvName)
		counter.status = (uint64)(statusFormat(stat.Status))
		counter.bytesIn = stat.Bin
		counter.bytesOut = stat.Bout
		counter.sessionNumber = stat.Scur
		counters = append(counters, &counter)
		num++
	}

	return counters, num
}


type GoBetweenServerBackendStat struct {
	Live bool `json:"live"`
	Active_connections uint64 `json:"active_connections"`
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

type GoBetweenServerBackend struct {
	Host string `json:"host"`
	Stats GoBetweenServerBackendStat `json:"stats"`
}

type GoBetweenServerStat struct {
	Backends []GoBetweenServerBackend `json:"backends"`
}

/* map to store: <listenerUuid, GBListerner> pair or  or <listenerUuid, HaProxyListener> */
var LbListeners map[string]interface{}
var goBetweenClient = &http.Client{
	Timeout: time.Second * 5,
}

func getGoBetweenStat(port string, server string )  (*GoBetweenServerStat, error){
	resp, err := goBetweenClient.Get(fmt.Sprintf("http://127.0.0.1:%s/servers/%s/stats", port, server))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("get goBetween stats failed because %v", err))
	}
	defer resp.Body.Close()

	stats := &GoBetweenServerStat{}
	body, err := ioutil.ReadAll(resp.Body)
	if err = json.Unmarshal(body, &stats); err != nil {
		return nil, errors.New(fmt.Sprintf("Unmarshal statistics failed %s", string(body)))
	}

	return stats, nil
}

func (this *GBListener) getGoBetweenCounters(listenerUuid string) ([]*LbCounter, int) {
	var counters []*LbCounter
	var stats *GoBetweenServerStat
	var err error
	num := 0

	port := this.apiPort
	if stats, err = getGoBetweenStat(port, listenerUuid); err != nil {
		log.Debugf("get getGoBetweenStat stats failed because %+v", err)
		return nil, 0
	}

	for _, stat := range stats.Backends {
		counter := LbCounter{}
		counter.listenerUuid = listenerUuid
		counter.ip = stat.Host
		if (stat.Stats.Live) {
			counter.status = 1
		} else {
			counter.status = 0
		}
		counter.bytesIn = stat.Stats.Rx
		counter.bytesOut = stat.Stats.Tx
		counter.sessionNumber = stat.Stats.Active_connections
		counters = append(counters, &counter)
		num++
	}

	return counters, num
}

func enableLbLog() {
	lb_log_file, err := ioutil.TempFile(LB_CONF_DIR, "rsyslog"); utils.PanicOnError(err)
	conf := `$ModLoad imudp
$UDPServerRun 514
local1.*     /var/log/haproxy.log`
	_, err = lb_log_file.Write([]byte(conf)); utils.PanicOnError(err)

	lb_log_rotatoe_file, err := ioutil.TempFile(LB_CONF_DIR, "rotation"); utils.PanicOnError(err)
	rotate_conf := `/var/log/haproxy.log {
size 10240k
rotate 20
compress
copytruncate
notifempty
missingok
}
/var/log/gobetween*.log {
size 10240k
rotate 20
compress
copytruncate
notifempty
missingok
}`
	_, err = lb_log_rotatoe_file.Write([]byte(rotate_conf)); utils.PanicOnError(err)

	bash := utils.Bash{
		Command: fmt.Sprintf("sudo mv %s /etc/rsyslog.d/haproxy.conf && sudo mv %s /etc/logrotate.d/haproxy && sudo /etc/init.d/rsyslog restart",
			lb_log_file.Name(), lb_log_rotatoe_file.Name()),
	}
	err = bash.Run();utils.PanicOnError(err)

}

func LbEntryPoint() {
	server.RegisterAsyncCommandHandler(REFRESH_LB_PATH, server.VyosLock(refreshLb))
	server.RegisterAsyncCommandHandler(DELETE_LB_PATH, server.VyosLock(deleteLb))
	server.RegisterAsyncCommandHandler(CREATE_CERTIFICATE_PATH, server.VyosLock(createCertificate))
}
