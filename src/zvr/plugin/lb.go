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
	"regexp"
	logger "github.com/Sirupsen/logrus"
	prom "github.com/prometheus/client_golang/prometheus"
	haproxy "github.com/bcicen/go-haproxy"
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
	conf := `global
maxconn {{.MaxConnection}}
log 127.0.0.1 local1
user vyos
group users
daemon
stats socket {{.SocketPath}} user vyos

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
	m["CertificatePath"] = makeCertificatePath(lb.CertificateUuid)
	m["SocketPath"] = makeLbSocketPath(lb)

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
		Command: fmt.Sprintf("sudo /opt/vyatta/sbin/haproxy -D -N %s -f %s -p %s -sf $(cat %s)", m["MaxConnection"], confPath, pidPath, pidPath),
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
	sockPath := makeLbSocketPath(lb)

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
	if e, _ := utils.PathExists(sockPath); e {
		err = os.Remove(sockPath); utils.LogError(err)
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

func init() {
	os.Mkdir(LB_ROOT_DIR, os.ModePerm)
	os.Mkdir(LB_SOCKET_DIR, os.ModePerm | os.ModeSocket)
	RegisterPrometheusCollector(NewLbPrometheusCollector())
}

type loadBalancerCollector struct {
	statusEntry *prom.Desc
	inByteEntry *prom.Desc
	outByteEntry *prom.Desc
	curSessionNumEntry *prom.Desc

	//vipUUIds map[string]string
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
	counters, num := getHaproxyCounter()
	for i := 0; i < num; i++ {
		cnt := counters[i]
		ch <- prom.MustNewConstMetric(c.statusEntry, prom.GaugeValue, float64(cnt.status), cnt.listenerUuid, cnt.ip)
		ch <- prom.MustNewConstMetric(c.inByteEntry, prom.GaugeValue, float64(cnt.bytesIn), cnt.listenerUuid, cnt.ip)
		ch <- prom.MustNewConstMetric(c.outByteEntry, prom.GaugeValue, float64(cnt.bytesOut), cnt.listenerUuid, cnt.ip)
		ch <- prom.MustNewConstMetric(c.curSessionNumEntry, prom.GaugeValue, float64(cnt.sessionNumber), cnt.listenerUuid, cnt.ip)
	}

	return nil
}

type haproxyCounter struct {
	listenerUuid    string
	ip              string
	status          uint64
	bytesIn         uint64
	bytesOut        uint64
	sessionNumber   uint64
}

func getLbListenerUuidFromFileName(path string) string {
	filename := filepath.Base(path)
	res := strings.Split(filename, ".")
	return res[0]
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

func getHaproxyCounter() ([]*haproxyCounter, int) {
	var counters []*haproxyCounter
	num := 0
	files, err := ioutil.ReadDir(LB_SOCKET_DIR)
	if err != nil {
		return nil, 0
	}

	for _, file := range files {
		client := &haproxy.HAProxyClient{
			Addr: "unix://" + LB_SOCKET_DIR + file.Name(),
		}

		listenerUuid := getLbListenerUuidFromFileName(file.Name())
		stats, err := client.Stats()
		if (err != nil) {
			logger.Infof("client.Stats failed %v", err)
			continue
		}

		for _, stat := range stats {
			if m, err := regexp.MatchString(LB_BACKEND_PREFIX_REG, stat.SvName); err != nil || !m  {
				continue
			}

			counter := haproxyCounter{}
			counter.listenerUuid = listenerUuid
			counter.ip = getIpFromLbStat(stat.SvName)
			counter.status = (uint64)(statusFormat(stat.Status))
			counter.bytesIn = stat.Bin
			counter.bytesOut = stat.Bout
			counter.sessionNumber = stat.Scur
			counters = append(counters, &counter)
			num++
		}
	}

	return counters, num
}

func LbEntryPoint() {
	server.RegisterAsyncCommandHandler(REFRESH_LB_PATH, server.VyosLock(refreshLb))
	server.RegisterAsyncCommandHandler(DELETE_LB_PATH, server.VyosLock(deleteLb))
	server.RegisterAsyncCommandHandler(CREATE_CERTIFICATE_PATH, server.VyosLock(createCertificate))
}
