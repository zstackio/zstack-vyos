package plugin

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	cidrman "github.com/EvilSuperstars/go-cidrman"
	"github.com/fatih/structs"
	prom "github.com/prometheus/client_golang/prometheus"
	haproxy "github.com/ruansteve/go-haproxy"
	log "github.com/sirupsen/logrus"
)

const (
	REFRESH_LB_PATH           = "/lb/refresh"
	REFRESH_LB_LOG_LEVEL_PATH = "/lb/log/level"
	DELETE_LB_PATH            = "/lb/delete"
	CREATE_CERTIFICATE_PATH   = "/certificate/create"
	DELETE_CERTIFICATE_PATH   = "/certificate/delete"
	CREATE_CERTIFICATES_PATH  = "/certificates/create"

	LB_MODE_HTTPS = "https"
	LB_MODE_HTTP  = "http"
	LB_MODE_TCP   = "tcp"
	LB_MODE_UDP   = "udp"

	LB_BACKEND_PREFIX_REG = "^nic-"

	LISTENER_MAP_SIZE = 128
	//reserve some sockets for haproxy if specify the parameter "ulimit-n"
	RESERVE_SOCK_COUNT = 100
	MAX_SOCK_COUNT     = 20971520

	LB_LOCAL_ICMP_FIREWALL_RULE_NUMBER = 2000
	HAPROXY_VERSION_1_6_9              = "1.6.9"
	HAPROXY_VERSION_2_1_0              = "2.1.0"
)

var (
	haproxyVersion     = HAPROXY_VERSION_1_6_9
	gobetweenListeners map[string]*GBListener
	haproxyListeners   map[string]*HaproxyListener
	EnableHaproxyLog   = true
)

func getLbRootPath() string {
	return filepath.Join(utils.GetZvrRootPath(), "lb/")
}

func getLbConfDir() string {
	return filepath.Join(utils.GetZvrRootPath(), "lb/conf/")
}

func getLbPidDir() string {
	return filepath.Join(utils.GetZvrRootPath(), "pid/")
}

func getLbCertificateRootPath() string {
	return filepath.Join(utils.GetZvrRootPath(), "certificate/")
}

func getLbSocketDir() string {
	return filepath.Join(utils.GetZvrRootPath(), "lb/sock/")
}

func getHaproxyBindPath() string {
	if utils.IsEuler2203() {
		return "/usr/sbin/haproxy"
	} else {
		return "/opt/vyatta/sbin/haproxy"
	}
}

const (
	TLS_CIPHER_POLICY_DEFAULT             = "tls_cipher_policy_default"
	TLS_CIPHER_POLICY_1_0                 = "tls_cipher_policy_1_0"
	TLS_CIPHER_POLICY_1_1                 = "tls_cipher_policy_1_1"
	TLS_CIPHER_POLICY_1_2                 = "tls_cipher_policy_1_2"
	TLS_CIPHER_POLICY_1_2_STRICT          = "tls_cipher_policy_1_2_strict"
	TLS_CIPHER_POLICY_1_2_STRICT_WITH_1_3 = "tls_cipher_policy_1_2_strict_with_1_3"

	LBSecurityPolicyConfiguration = `
    ssl-default-bind-ciphers %s
    ssl-default-bind-options %s
	`
)

const (
	LBSecurityPolicyCommonCiphers      = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA"
	LBSecurityPolicy1_2_3CommonCiphers = "AES128-GCM-SHA256:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"
	LBSecurityPolicystrict3OnlyCiphers = "TLS_AES_256_GCM_SHA384:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA"
)

type BackendServerInfo struct {
	Ip     string `json:"ip"`
	Weight int    `json:"weight"`
}

type ServerGroupInfo struct {
	Name            string              `json:"name"`
	ServerGroupUuid string              `json:"serverGroupUuid"`
	BackendServers  []BackendServerInfo `json:"backendServers"`
	IsDefault       bool                `json:"isDefault"`
}

type RedirectRuleInfo struct {
	RedirectRuleUuid string `json:"redirectRuleUuid"`
	AclUuid          string `json:"aclUuid"`
	RedirectRule     string `json:"redirectRule"`
	ServerGroupUuid  string `json:"serverGroupUuid"`
}

type LbInfo struct {
	LbUuid             string             `json:"lbUuid"`
	ListenerUuid       string             `json:"listenerUuid"`
	Vip                string             `json:"vip"`
	Vip6               string             `json:"vip6"`
	PublicNic          string             `json:"publicNic"`
	EnableFullLog      bool               `json:"enableFullLog"`
	NicIps             []string           `json:"nicIps"`
	InstancePort       int                `json:"instancePort"`
	LoadBalancerPort   int                `json:"loadBalancerPort"`
	Mode               string             `json:"mode"`
	Parameters         []string           `json:"parameters"`
	CertificateUuid    string             `json:"certificateUuid"`
	SecurityPolicyType string             `json:"securityPolicyType"`
	ServerGroups       []ServerGroupInfo  `json:"serverGroups"`
	RedirectRules      []RedirectRuleInfo `json:"redirectRules"`
}

type CertificateInfo struct {
	Uuid        string `json:"uuid"`
	Certificate string `json:"certificate"`
}

type certificatesCmd struct {
	Certs map[string]string `json:"certs"`
}

type deleteCertificateCmd struct {
	Uuid string `json:"uuid"`
}

type LbParams struct {
	healthCheckProtocl  string
	healthCheckPort     int
	healthCheckInterval int
	healthCheckTimeout  int
	healthyThreshold    uint
	unhealthyThreshold  uint

	httpMode              string
	maxConnection         int
	minConnection         int
	connectionIdleTimeout int
	Nbprocess             int
	httpRedirectHttps     bool
	accessControlStatus   bool
	balancerAlgorithm     string
	aclEntry              []string
}

func ParseLbParams(lb LbInfo) LbParams {
	param := LbParams{}
	for _, p := range lb.Parameters {
		kv := strings.Split(p, "::")
		if len(kv) < 2 {
			continue
		}
		switch kv[0] {
		case "healthCheckTarget":
			mp := strings.Split(kv[1], ":")
			cport := mp[1]
			if cport == "default" {
				param.healthCheckPort = 0
			} else {
				param.healthCheckPort, _ = strconv.Atoi(cport)
			}
			param.healthCheckProtocl = mp[0]

		case "healthCheckInterval":
			param.healthCheckInterval, _ = strconv.Atoi(kv[1])

		case "healthCheckTimeout":
			param.healthCheckTimeout, _ = strconv.Atoi(kv[1])

		case "httpMode":
			param.httpMode = kv[1]

		case "unhealthyThreshold":
			v, _ := strconv.Atoi(kv[1])
			param.unhealthyThreshold = uint(v)

		case "healthyThreshold":
			v, _ := strconv.Atoi(kv[1])
			param.healthyThreshold = uint(v)

		case "maxConnection":
			param.maxConnection, _ = strconv.Atoi(kv[1])

		case "connectionIdleTimeout":
			param.connectionIdleTimeout, _ = strconv.Atoi(kv[1])
		case "Nbprocess":
			param.Nbprocess, _ = strconv.Atoi(kv[1])

		case "httpRedirectHttps":
			if kv[1] == "disable" {
				param.httpRedirectHttps = false
			} else {
				param.httpRedirectHttps = true
			}
		case "accessControlStatus":
			if kv[1] == "disable" {
				param.accessControlStatus = false
			} else {
				param.accessControlStatus = true
			}
		case "balancerAlgorithm":
			param.balancerAlgorithm = kv[1]
		}
	}

	return param
}

type Listener interface {
	createListenerServiceConfigure(lb LbInfo) (err error)
	checkIfListenerServiceUpdate(origChecksum string, currChecksum string) (bool, error)
	startListenerService() (ret int, err error)
	stopListenerService() (err error)
	postActionListenerServiceStop() (ret int, err error)
	getLbCounters(listenerUuid string, listener Listener) <-chan CounterChanData
	getLastCounters() (lastCounters *CachedCounters)
	getIptablesRule() ([]*utils.IpTableRule, string)
	getIcmpIptablesRule() ([]*utils.IpTableRule, string)
	getSynIptablesRule() (*utils.IpTableRule, string)
	getLbInfo() (lb LbInfo)
	startPidMonitor()
	stopPidMonitor()
	getMaxSession() int
}

type CachedCounters struct {
	counters []*LbCounter
	ch       <-chan CounterChanData
}

type CounterChanData struct {
	counters []*LbCounter
}

// the listener implemented with HaProxy
type HaproxyListener struct {
	lb                   LbInfo
	confPath             string
	pidPath              string
	sockPath             string
	firewallDes          string
	firewallLocalICMPDes string
	maxConnect           string
	maxSession           int //same to maxConnect
	aclPath              string
	pm                   *utils.PidMon
	lastCounters         *CachedCounters
}

// the listener implemented with gobetween
type GBListener struct {
	lb                   LbInfo
	confPath             string
	pidPath              string
	firewallDes          string
	firewallLocalICMPDes string
	apiPort              string // restapi binding port range from 50000-60000
	maxConnect           string
	maxSession           int //same to maxConnect
	aclPath              string
	pm                   *utils.PidMon
	lastCounters         *CachedCounters
}

func getGBApiPort(confPath string, pidPath string) (port string) {
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo /bin/netstat -tnlp"),
	}

	if ret, out, _, err := bash.RunWithReturn(); ret != 0 || err != nil {
		bash.PanicIfError()
	} else {
		port = ""
		pid, _ := utils.FindFirstPIDByPSExtern(true, confPath)
		if pid > 0 {
			//get current port used
			kv := strings.SplitN(out, "\n", -1)
			for start := 50000; start < 60000; start++ {
				port = strconv.Itoa(start)
				//find the record ":port * pid/gobetween"
				if strings.Contains(out, ":"+port) {
					for _, str := range kv {
						if strings.Contains(str, ":"+port) && strings.Contains(str, strconv.Itoa(pid)+"/gobetween") {
							//log.Debugf("lb %s pid: %v api port: %v ", confPath, pid, port)
							return port
						}
					}
				}

			}
			//log.Debugf("%v port&%d not found in \n %v\n", pidPath, pid, out)
		}

		for start := 50000; start < 60000; start++ {
			if !strings.Contains(out, ":"+strconv.Itoa(start)) {
				port = strconv.Itoa(start)
				log.Debugf("lb %s pid: %v api port: %v ", confPath, pid, port)
				break
			}
		}

	}

	return port
}

func GetListener(lb LbInfo) Listener {
	pidPath := makeLbPidFilePath(lb)
	confPath := makeLbConfFilePath(lb)
	sockPath := makeLbSocketPath(lb)
	aclPath := makeLbAclConfFilePath(lb)
	des := makeLbFirewallRuleDescription(lb)
	localICMPDes := makeLbFirewallLocalICMPRuleDescription(lb)

	switch lb.Mode {
	case "udp":
		port := getGBApiPort(confPath, pidPath)
		if port == "" {
			log.Errorf("there is no free port for rest api for listener: %v \n", lb.ListenerUuid)
			return nil
		}
		lastCounters := &CachedCounters{}
		return &GBListener{lb: lb, confPath: confPath, pidPath: pidPath, firewallDes: des, firewallLocalICMPDes: localICMPDes, apiPort: port, aclPath: aclPath, lastCounters: lastCounters}
	case "tcp", "https", "http":
		lastCounters := &CachedCounters{}
		return &HaproxyListener{lb: lb, confPath: confPath, pidPath: pidPath, firewallDes: des, firewallLocalICMPDes: localICMPDes, sockPath: sockPath, aclPath: aclPath, lastCounters: lastCounters}
	default:
		utils.PanicOnError(fmt.Errorf("No such listener %v", lb.Mode))
	}
	return nil
}

/*transform ip range into a series of cidr networks*/
func ipRange2Cidrs(ipEntry []string) []string {
	entry := make([]string, 0)
	for _, e := range ipEntry {
		if strings.Contains(e, "-") {
			ips := strings.Split(e, "-")
			o, err := cidrman.IPRangeToCIDRs(ips[0], ips[1])
			utils.PanicOnError(err)
			entry = append(entry, o...)
		} else {
			entry = append(entry, e)
		}
	}

	return entry
}

func parseListenerPrameter(lb LbInfo) (map[string]interface{}, error) {
	sort.Stable(sort.StringSlice(lb.NicIps))
	m := structs.Map(lb)
	weight := make(map[string]string)

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
			m["HealthCheckProtocol"] = mp[0]
		} else if k == "balancerWeight" {
			mp := strings.Split(v, "::")
			weight[mp[0]] = mp[1]
		} else if k == "healthCheckParameter" {
			mp := strings.Split(v, ":")
			m["HttpChkMethod"] = mp[0]
			m["HttpChkUri"] = mp[1]
			if mp[2] != "http_2xx" {
				code := map[string]string{"http_2xx": "2", "http_3xx": "3", "http_4xx": "4", "http_5xx": "5"}
				expect := "^["
				for _, o := range strings.Split(mp[2], ",") {
					expect = expect + code[o]
				}
				m["HttpChkExpect"] = expect + "]"
			} else {
				m["HttpChkExpect"] = mp[2]
			}
		} else {
			m[strings.Title(k)] = v
		}
	}

	if lb.SecurityPolicyType == TLS_CIPHER_POLICY_1_0 {
		m["SecurityOptions"] = fmt.Sprintf(LBSecurityPolicyConfiguration, LBSecurityPolicyCommonCiphers+":"+LBSecurityPolicy1_2_3CommonCiphers, "no-sslv3 no-tlsv13 no-tls-tickets")
	} else if lb.SecurityPolicyType == TLS_CIPHER_POLICY_1_1 {
		m["SecurityOptions"] = fmt.Sprintf(LBSecurityPolicyConfiguration, LBSecurityPolicyCommonCiphers+":"+LBSecurityPolicy1_2_3CommonCiphers, "no-sslv3 no-tlsv10 no-tlsv13 no-tls-tickets")
	} else if lb.SecurityPolicyType == TLS_CIPHER_POLICY_1_2 {
		m["SecurityOptions"] = fmt.Sprintf(LBSecurityPolicyConfiguration, LBSecurityPolicyCommonCiphers+":"+LBSecurityPolicy1_2_3CommonCiphers, "no-sslv3 no-tlsv10 no-tlsv11 no-tlsv13 no-tls-tickets")
	} else if lb.SecurityPolicyType == TLS_CIPHER_POLICY_1_2_STRICT {
		m["SecurityOptions"] = fmt.Sprintf(LBSecurityPolicyConfiguration, LBSecurityPolicyCommonCiphers, "no-sslv3 no-tlsv10 no-tlsv11 no-tlsv13 no-tls-tickets")
	} else if lb.SecurityPolicyType == TLS_CIPHER_POLICY_1_2_STRICT_WITH_1_3 {
		m["SecurityOptions"] = fmt.Sprintf(LBSecurityPolicyConfiguration, LBSecurityPolicyCommonCiphers+":"+LBSecurityPolicystrict3OnlyCiphers, "no-sslv3 no-tlsv10 no-tlsv11 no-tlsv12 no-tls-tickets")
	}

	m["CertificatePath"] = makeCertificatePath(lb.CertificateUuid)
	m["SocketPath"] = makeLbSocketPath(lb)
	m["Weight"] = weight

	var combinedServerGroups []ServerGroupInfo
	var isAclRedirect bool
	var defaultServerGroup ServerGroupInfo

	if (lb.RedirectRules != nil) && (len(lb.RedirectRules) > 0) && ((lb.Mode == "http") || (lb.Mode == "https")) {
		isAclRedirect = true
		m["IsAclRedirect"] = "enable"
	} else {
		m["IsAclRedirect"] = "disable"
	}

	if isAclRedirect {
		m["RedirectRules"] = lb.RedirectRules
		for _, sGroup := range lb.ServerGroups {
			if sGroup.IsDefault {
				defaultServerGroup.BackendServers = append(defaultServerGroup.BackendServers, sGroup.BackendServers...)
			} else {
				combinedServerGroups = append(combinedServerGroups, sGroup)
			}
		}
	} else {
		for _, sGroup := range lb.ServerGroups {
			defaultServerGroup.BackendServers = append(defaultServerGroup.BackendServers, sGroup.BackendServers...)
		}
	}

	if len(defaultServerGroup.BackendServers) > 0 {
		defaultServerGroup.Name = "defaultServerGroup"
		defaultServerGroup.ServerGroupUuid = "default-" + lb.ListenerUuid
		defaultServerGroup.IsDefault = true
		log.Debugf("defaultServerGroupUuid change to %s", defaultServerGroup.ServerGroupUuid)
		m["DefaultServerGroupUuid"] = defaultServerGroup.ServerGroupUuid
		combinedServerGroups = append(combinedServerGroups, defaultServerGroup)
	} else {
		m["DefaultServerGroupUuid"] = ""
		log.Debugf("defaultServerGroupUuid is null")
	}

	if len(combinedServerGroups) > 0 {
		m["ServerGroups"] = combinedServerGroups
	} else {
		m["ServerGroups"] = []ServerGroupInfo{}
	}

	if m["TcpProxyProtocol"] == "v1" {
		m["ServerSendProxy"] = "send-proxy"
	} else if m["TcpProxyProtocol"] == "v2" {
		m["ServerSendProxy"] = "send-proxy-v2"
	} else {
		m["ServerSendProxy"] = ""
	}

	if m["HttpCompressAlgos"] != nil && m["HttpCompressAlgos"] != "" {
		m["HttpCompressAlgos"] = "compression algo " + m["HttpCompressAlgos"].(string)
		m["HttpCompressType"] = "compression type text/xml text/plain text/css application/javascript application/x-javascript application/rss+xml application/atom+xml application/xml application/json"
	}

	if lb.EnableFullLog {
		if lb.Mode == "tcp" {
			m["OptionLog"] = "option tcplog"
		} else if lb.Mode == "http" || lb.Mode == "https" {
			m["OptionLog"] = "option httplog"
		}
	}

	vips := make([]string, 0)
	if lb.Vip != "" {
		vips = append(vips, lb.Vip)
	}
	if lb.Vip6 != "" {
		vips = append(vips, lb.Vip6)
	}
	if m["HttpVersions"] != nil {
		m["HttpVersions"] = fmt.Sprintf("alpn %s", m["HttpVersions"])
	} else {
		m["HttpVersions"] = ""
	}

	m["Vips"] = vips
	log.Debugf("refresh lb vips %+v", vips)
	log.Debugf("refresh lb httpvertsion %+v", m["HttpVersions"])
	return m, nil
}

func getListenerMaxCocurrenceSocket(maxConnect string) string {
	maxSocket, err := strconv.Atoi(maxConnect)
	utils.PanicOnError(err)
	maxSocket = maxSocket*2 + RESERVE_SOCK_COUNT

	if maxSocket > MAX_SOCK_COUNT {
		log.Errorf("invalid prameter maxconn %v,please check it", maxConnect)
		maxSocket = MAX_SOCK_COUNT
	}
	return strconv.Itoa(maxSocket)
}

func (this *HaproxyListener) startPidMonitor() {
	if _, ok := haproxyListeners[this.lb.ListenerUuid]; !ok {
		pid, err := utils.ReadPid(this.pidPath)
		if err == nil {
			this.pm = utils.NewPidMon(pid, func() int {
				log.Warnf("start haproxy in PidMon for %s", this.lb.ListenerUuid)
				_, err := this.startListenerService()
				if err != nil {
					log.Warnf("failed to respawn haproxy: %s", err)
					return -1
				}

				pid, err := utils.ReadPid(this.pidPath)
				if err != nil {
					log.Warnf("failed to read haproxy pid: %s", err)
					return -1
				}

				return pid
			})
			log.Debugf("created haproxy PidMon for %s", this.lb.ListenerUuid)
			haproxyListeners[this.lb.ListenerUuid] = this
			this.pm.Start()
		} else {
			log.Warnf("failed to get haproxy pid: %s", err)
			return
		}
	} else {
		log.Debugf("haproxy PidMon for %s already created", this.lb.ListenerUuid)
	}
}

func (this *HaproxyListener) stopPidMonitor() {
	if lb, ok := haproxyListeners[this.lb.ListenerUuid]; ok {
		log.Warnf("stop haproxy PidMon for %s", this.lb.ListenerUuid)
		lb.pm.Stop()
		delete(haproxyListeners, this.lb.ListenerUuid)
	} else {
		log.Warnf("haproxy PidMon for %s not created", this.lb.ListenerUuid)
	}
}

func (this *HaproxyListener) createListenerServiceConfigure(lb LbInfo) (err error) {
	conf := ` # This file is auto-generated, edit with caution!
    global
    maxconn {{.MaxConnection}}
{{if .EnableHaproxyLog}}
    log 127.0.0.1 local1
{{end}}
    #user vyos
    #group users
    uid {{.uid}}
    gid {{.gid}}
    daemon
    #stats socket {{.SocketPath}} user vyos
    stats socket {{.SocketPath}} gid {{.gid}} uid {{.uid}}
    ulimit-n {{.ulimit}}
{{- if eq .Mode "https" }}
    tune.ssl.default-dh-param 2048
{{end}}
{{if eq .HaproxyVersion "1.6.9"}}
    nbproc {{.Nbprocess}}
{{else}}
    nbthread {{.Nbprocess}}
{{end}}
	{{.SecurityOptions}}
defaults
    log global
    option dontlognull
    option redispatch
{{- if eq .Mode "https" "http"}}
    option {{.HttpMode}}
{{end}}
    {{.HttpCompressAlgos}}
    {{.HttpCompressType}}


frontend {{.ListenerUuid}}
{{- if eq .Mode "https"}}
    mode http
{{- else}}
    mode {{.Mode}}
{{- end }}
{{if ne .Mode "tcp"}}
    option forwardfor
{{end}}

{{- with .Vips }}
{{- range . }}
{{- if eq $.Mode "https"}}
    bind {{ . }}:{{$.LoadBalancerPort}} ssl crt {{$.CertificatePath}} {{$.HttpVersions}}
{{- else }}
    bind {{ . }}:{{$.LoadBalancerPort}}
{{- end }}
{{- end }}
{{- end }}

    timeout client {{.ConnectionIdleTimeout}}s
    {{.OptionLog}}

{{- if  $.HttpRedirectHttps}}
{{- if eq $.HttpRedirectHttps "enable"}}
    http-request redirect location https://%[req.hdr(host),regsub(:\d+$,,)]:{{$.RedirectPort}}%[capture.req.uri,regsub(/$,,)] code {{$.StatusCode}} unless { ssl_fc }
{{- end }}
{{- end }}
{{- if eq .Mode "https"}}
	http-request redirect scheme https code 301 unless { ssl_fc }
{{- end}}

{{- if eq .AccessControlStatus "enable" }}
{{- if eq .AclType "black" "white" }}
    #acl status: {{.AccessControlStatus}} ip entty md5: {{.AclEntryMd5}}
    acl {{.ListenerUuid}} src -f {{.AclConfPath}}
{{- end }}
{{- if eq .AclType "black"}}
    tcp-request connection reject if {{.ListenerUuid}}
{{- end }}
{{- if eq .AclType "white" }}
    tcp-request connection reject unless {{.ListenerUuid}}
{{- end }}

{{- end}}


{{- if eq .IsAclRedirect "enable" }}
{{with .RedirectRules }}
{{- range . }}
    acl {{.RedirectRuleUuid}} {{ .RedirectRule }}
    use_backend {{ .ServerGroupUuid }} if {{.RedirectRuleUuid }}
{{- end }}
{{- end }}

{{- end }}

{{- if ne .DefaultServerGroupUuid "" }}
    default_backend {{ .DefaultServerGroupUuid }}
{{ end }}

{{- with .ServerGroups }}
{{- range . }}
backend {{ .ServerGroupUuid}}

{{- if eq $.Mode "https"}}
    mode http
{{- else}}
    mode {{ $.Mode}}
{{- end }}	
    balance {{ $.BalancerAlgorithm}}
    timeout server {{$.ConnectionIdleTimeout}}s
    timeout connect 60s
{{- if eq $.SessionPersistence "insert"}}
    cookie  zstack_cookie  insert  nocache  maxidle {{$.SessionIdleTimeout}}s
{{- else }}
{{- if eq $.SessionPersistence "rewrite"}}
    cookie  {{$.CookieName}}  rewrite
{{- end }}
{{- end }}

{{- if eq $.HealthCheckProtocol "http" }}
    option httpchk {{$.HttpChkMethod}} {{$.HttpChkUri}}
{{- if ne $.HttpChkExpect "http_2xx" }}
    http-check expect rstatus {{$.HttpChkExpect}}
{{- end }}
{{- end }}

{{- with .BackendServers }}
{{- range . }}
{{- if eq $.BalancerAlgorithm "static-rr" }}
{{- if eq $.SessionPersistence "insert" "rewrite"}}
    server nic-{{.Ip}} {{.Ip}}:{{$.InstancePort}} cookie {{.Ip}} weight {{.Weight}} check port {{$.CheckPort}} inter {{$.HealthCheckInterval}}s rise {{$.HealthyThreshold}} fall {{$.UnhealthyThreshold}} {{$.ServerSendProxy}}
{{- else }}    
    server nic-{{.Ip}} {{.Ip}}:{{$.InstancePort}} weight {{.Weight}} check port {{$.CheckPort}} inter {{$.HealthCheckInterval}}s rise {{$.HealthyThreshold}} fall {{$.UnhealthyThreshold}} {{$.ServerSendProxy}}
{{- end }}
{{- else }}
{{- if eq $.SessionPersistence "insert" "rewrite"}}
    server nic-{{.Ip}} {{.Ip}}:{{$.InstancePort}} cookie {{.Ip}} check port {{$.CheckPort}} inter {{$.HealthCheckInterval}}s rise {{$.HealthyThreshold}} fall {{$.UnhealthyThreshold}} {{$.ServerSendProxy}}
{{- else }}
    server nic-{{.Ip}} {{.Ip}}:{{$.InstancePort}} check port {{$.CheckPort}} inter {{$.HealthCheckInterval}}s rise {{$.HealthyThreshold}} fall {{$.UnhealthyThreshold}} {{$.ServerSendProxy}}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
			
{{- end }}
{{- end }}
`
	var buf, acl_buf bytes.Buffer
	var m map[string]interface{}
	tmpl, err := template.New("conf").Parse(conf)
	utils.PanicOnError(err)
	m, err = parseListenerPrameter(lb)
	utils.PanicOnError(err)
	this.maxConnect = m["MaxConnection"].(string)
	this.maxSession, _ = strconv.Atoi(this.maxConnect)
	if strings.EqualFold(m["BalancerAlgorithm"].(string), "weightroundrobin") {
		m["BalancerAlgorithm"] = "static-rr"
	}
	m["ulimit"] = getListenerMaxCocurrenceSocket(this.maxConnect)

	if _, exist := m["AccessControlStatus"]; !exist {
		m["AccessControlStatus"] = "disable"
	}

	if _, exist := m["AclType"]; !exist {
		m["AclType"] = "black"
	}

	if _, exist := m["AclEntry"]; !exist {
		m["AclEntry"] = ""
	}
	if strings.EqualFold(m["AclEntry"].(string), "") {
		m["AccessControlStatus"] = "disable"
	} else {
		m["AclConfPath"] = this.aclPath
		m["AclEntryMd5"] = md5.Sum([]byte(m["AclEntry"].(string)))
	}
	if _, exist := m["Nbprocess"]; !exist {
		m["Nbprocess"] = "1"
	}
	m["HaproxyVersion"] = haproxyVersion
	m["EnableHaproxyLog"] = EnableHaproxyLog

	if mode, exist := m["Mode"]; exist && (mode == "http" || mode == "https") {
		if _, exist := m["HttpMode"]; !exist {
			m["HttpMode"] = "http-server-close"
		}
	}

	if _, exist := m["SessionPersistence"]; !exist {
		m["SessionPersistence"] = "disable"
	}

	user := "zstack"
	if utils.IsVYOS() {
		user = "vyos"
	}
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo id -u " + user),
	}
	_, result, _, _ := bash.RunWithReturn()
	result = strings.Replace(result, "\n", "", -1)
	_, er := strconv.Atoi(result)
	utils.PanicOnError(er)
	m["uid"] = result

	group := "zstack"
	if utils.IsVYOS() {
		group = "vyos"
	}
	b := utils.Bash{
		Command: fmt.Sprintf("sudo id -g " + group),
	}
	_, re, _, _ := b.RunWithReturn()
	re = strings.Replace(re, "\n", "", -1)
	_, e := strconv.Atoi(re)
	utils.PanicOnError(e)
	m["gid"] = re

	err = utils.MkdirForFile(this.aclPath, 0755)
	utils.PanicOnError(err)
	acl_buf.WriteString(strings.Join(ipRange2Cidrs(strings.Split(m["AclEntry"].(string), ",")), "\n"))
	err = ioutil.WriteFile(this.aclPath, acl_buf.Bytes(), 0755)
	utils.PanicOnError(err)
	err = tmpl.Execute(&buf, m)
	utils.PanicOnError(err)
	err = utils.MkdirForFile(this.pidPath, 0755)
	utils.PanicOnError(err)
	err = utils.MkdirForFile(this.confPath, 0755)
	utils.PanicOnError(err)
	err = ioutil.WriteFile(this.confPath, buf.Bytes(), 0755)
	utils.PanicOnError(err)
	LbListeners[this.lb.ListenerUuid] = this
	return err
}

func (this *HaproxyListener) startListenerService() (ret int, err error) {
	pids := this.getPids()

	var bash utils.Bash
	if len(pids) > 0 {
		bash = utils.Bash{
			Command: fmt.Sprintf("sudo %s -D -N %s -f %s -p %s -sf %s",
				getHaproxyBindPath(), this.maxConnect, this.confPath, this.pidPath, strings.Join(pids, " ")),
		}
	} else {
		bash = utils.Bash{
			Command: fmt.Sprintf("sudo %s  -D -N %s -f %s -p %s",
				getHaproxyBindPath(), this.maxConnect, this.confPath, this.pidPath),
		}
	}
	var stderr string
	var stdout string
	ret, stdout, stderr, err = bash.RunWithReturn()
	if err != nil {
		return ret, errors.New(fmt.Sprintf("shell failure[command: %v, return code: %v, stdout: %v, stderr: %v", bash.Command, ret, stdout, stderr))
	}
	return ret, err
}

func (this *HaproxyListener) checkIfListenerServiceUpdate(origChecksum string, currChecksum string) (bool, error) {
	pid, err := utils.FindFirstPIDByPS(this.confPath, this.pidPath)
	if pid > 0 {
		//log.Debugf("lb %s pid: %v orig: %v curr: %v", this.confPath, pid, origChecksum, currChecksum)
		return strings.EqualFold(origChecksum, currChecksum) == false, nil
	} else if pid == -1 {
		err = nil
	}
	return true, err
}

func configureInternalFirewallRule(tree *server.VyosConfigTree, des string, rules ...string) (err error) {
	/*support to access lb vip from all the private nics */
	err = nil
	priNics := utils.GetPrivteInterface()
	for _, priNic := range priNics {
		if r := tree.FindFirewallRuleByDescription(priNic, "local", des); r == nil {
			tree.SetFirewallOnInterface(priNic, "local", rules...)
		}
	}
	return
}

func cleanInternalFirewallRule(tree *server.VyosConfigTree, des string) (err error) {
	/*support to access lb vip from all the private nics */
	err = nil
	priNics := utils.GetPrivteInterface()
	for _, priNic := range priNics {
		if r := tree.FindFirewallRuleByDescription(priNic, "local", des); r != nil {
			r.Delete()
		}
	}
	return
}

func (this *HaproxyListener) getPids() []string {
	pids := []string{}
	bash := utils.Bash{
		Command: fmt.Sprintf("ps aux | grep %s | grep -v grep | awk '{print $2}'", this.confPath),
	}
	ret, o, _, err := bash.RunWithReturn()
	if ret == 0 && err == nil {
		o = strings.TrimSpace(o)
		for _, pid := range strings.Split(o, "\n") {
			if pid != "" {
				pids = append(pids, pid)
			}
		}
	}

	return pids
}

func (this *HaproxyListener) stopListenerService() (err error) {
	pids := this.getPids()
	if len(pids) > 0 {
		for _, pid := range pids {
			p, err := strconv.Atoi(pid)
			utils.PanicOnError(err)
			err = utils.KillProcess(p)
			utils.PanicOnError(err)
		}
	} else {
		err = nil
	}

	if this.lb.Vip != "" {
		t := utils.ConnectionTrackTuple{IsNat: false, IsDst: true, Ip: this.lb.Vip, Protocol: "tcp",
			PortStart: this.lb.LoadBalancerPort, PortEnd: this.lb.LoadBalancerPort}
		t.CleanConnTrackConnection()
	} else {
		t := utils.ConnectionTrackTuple{IsNat: false, IsDst: true, Ip: this.lb.Vip6, Protocol: "tcp",
			PortStart: this.lb.LoadBalancerPort, PortEnd: this.lb.LoadBalancerPort}
		t.CleanConnTrackConnection()
	}

	return err
}

func (this *HaproxyListener) getIptablesRule() ([]*utils.IpTableRule, string) {
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic)
	utils.PanicOnError(err)

	if this.lb.Vip == "" {
		return []*utils.IpTableRule{}, nicname
	}

	rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.LbRuleComment)
	rule.SetProto(utils.IPTABLES_PROTO_TCP).SetDstPort(fmt.Sprintf("%d", this.lb.LoadBalancerPort)).SetDstIp(this.lb.Vip + "/32")

	return []*utils.IpTableRule{rule}, nicname
}

func (this *HaproxyListener) getIcmpIptablesRule() ([]*utils.IpTableRule, string) {
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic)
	utils.PanicOnError(err)

	rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.LbRuleComment)
	rule.SetProto(utils.IPTABLES_PROTO_ICMP).SetDstIp(this.lb.Vip + "/32")

	return []*utils.IpTableRule{rule}, nicname
}

func (this *HaproxyListener) getSynIptablesRule() (*utils.IpTableRule, string) {
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic)
	utils.PanicOnError(err)

	rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_DROP).SetComment(utils.LbRuleComment)
	rule.SetDstIp(this.lb.Vip + "/32").SetProto(utils.IPTABLES_PROTO_TCP).SetDstPort(fmt.Sprintf("%d", this.lb.LoadBalancerPort))
	rule.SetTcpFlags([]string{"SYN"})

	return rule, nicname
}

func (this *HaproxyListener) getLbInfo() (lb LbInfo) {
	lb = this.lb
	return
}

func (this *HaproxyListener) getLastCounters() *CachedCounters {
	return this.lastCounters
}

func (this *HaproxyListener) getMaxSession() int {
	return this.maxSession
}

func (this *HaproxyListener) postActionListenerServiceStop() (ret int, err error) {
	delete(LbListeners, this.lb.ListenerUuid)

	if e, _ := utils.PathExists(this.pidPath); e {
		err = os.Remove(this.pidPath)
		utils.LogError(err)
	}
	if e, _ := utils.PathExists(this.confPath); e {
		err = os.Remove(this.confPath)
		utils.LogError(err)
	}
	if e, _ := utils.PathExists(this.sockPath); e {
		err = os.Remove(this.sockPath)
		utils.LogError(err)
	}

	if e, _ := utils.PathExists(this.aclPath); e {
		err = os.Remove(this.aclPath)
		utils.LogError(err)
	}

	return 0, err
}

func (this *GBListener) adaptListenerParameter(m map[string]interface{}) (map[string]interface{}, error) {
	if strings.EqualFold(m["BalancerAlgorithm"].(string), "weightroundrobin") {
		m["BalancerAlgorithm"] = "weight"
	} else if strings.EqualFold(m["BalancerAlgorithm"].(string), "source") {
		m["BalancerAlgorithm"] = "iphash1"
	}
	return m, nil
}

func (this *GBListener) createListenerServiceConfigure(lb LbInfo) (err error) {
	conf := `[api]
enabled = true  # true | false
bind = ":{{.ApiPort}}"  # bind host:port
[logging]
level = "info"   # "debug" | "info" | "warn" | "error"
#output = "/var/log/gobetween_{{.ListenerUuid}}.log" # "stdout" | "stderr" | "/path/to/gobetween.log"
output = "/var/log/gobetween.log"

[servers.{{.ListenerUuid}}]
bind = "{{.Vip}}:{{.LoadBalancerPort}}"
protocol = "{{.Mode}}"
balance = "{{.BalancerAlgorithm}}"
max_connections = {{.MaxConnection}}
client_idle_timeout = "{{.ConnectionIdleTimeout}}s"
backend_idle_timeout = "{{.ConnectionIdleTimeout}}s"
backend_connection_timeout = "60s"
[servers.{{.ListenerUuid}}.udp] # (optional)
max_requests  = 0     # (optional) if > 0 accepts no more requests than max_requests and closes session (since 0.5.0)
max_responses = 0    # (required) if > 0 accepts no more responses that max_responses from backend and closes session (will be optional since 0.5.0)
{{if eq .AccessControlStatus "enable"}}
    [servers.{{.ListenerUuid}}.access]
    {{- if eq .AclType "black" }}
    default = "allow"
    {{- else }}
    default = "deny"
    {{- end }}
    rules = [
    {{- if eq .AclType "black" }}
    {{- range $entry := $.AclEntry }}
        "deny {{$entry}}",
    {{- end }}
    {{- else }}
    {{- range $entry := $.AclEntry }}
        "allow {{$entry}}",
    {{- end }}
    {{- end }}
    ]
{{end}}
    [servers.{{.ListenerUuid}}.discovery]
    kind = "static"
    failpolicy = "keeplast"
    static_list = [
    {{- if eq $.BalancerAlgorithm "weight" }}
	{{- range $ip, $weight := $.Weight }}
      "{{$ip}}:{{$.CheckPort}} weight={{$weight}}",
	{{- end }}
    {{- else }}
	{{- range $index, $ip := $.NicIps }}
      "{{$ip}}:{{$.CheckPort}}",
        {{- end }}
    {{- end }}
    ]

    [servers.{{.ListenerUuid}}.healthcheck]
    fails = {{$.UnhealthyThreshold}}
    passes = {{$.HealthyThreshold}}
    interval = "{{$.HealthCheckInterval}}s"
    timeout = "{{$.HealthCheckTimeout}}s"
    kind = "exec"
    exec_command = "/usr/share/healthcheck.sh"  # (required) command to execute
    exec_expected_positive_output = "success"           # (required) expected output of command in case of success
    exec_expected_negative_output = "fail"
`

	var buf bytes.Buffer
	var m map[string]interface{}

	tmpl, err := template.New("conf").Parse(conf)
	utils.PanicOnError(err)
	m, err = parseListenerPrameter(lb)
	utils.PanicOnError(err)
	m, err = this.adaptListenerParameter(m)
	utils.PanicOnError(err)
	m["ApiPort"] = this.apiPort
	if _, exist := m["AccessControlStatus"]; !exist {
		m["AccessControlStatus"] = "disable"
	}

	if _, exist := m["AclType"]; !exist {
		m["AclType"] = "black"
	}

	if _, exist := m["AclEntry"]; !exist {
		m["AclEntry"] = ""
	}

	if strings.EqualFold(m["AclEntry"].(string), "") {
		m["AccessControlStatus"] = "disable"
	} else {
		m["AclEntry"] = ipRange2Cidrs(strings.Split(m["AclEntry"].(string), ","))
	}

	this.maxConnect = m["MaxConnection"].(string)
	this.maxSession, _ = strconv.Atoi(this.maxConnect)
	log.Debugf("lb aclstatus:%v type: %v entry: %v ", m["AccessControlStatus"].(string), m["AclType"], m["AclEntry"])

	err = tmpl.Execute(&buf, m)
	utils.PanicOnError(err)
	err = utils.MkdirForFile(this.pidPath, 0755)
	utils.PanicOnError(err)
	err = utils.MkdirForFile(this.confPath, 0755)
	utils.PanicOnError(err)
	err = ioutil.WriteFile(this.confPath, buf.Bytes(), 0755)
	utils.PanicOnError(err)
	LbListeners[this.lb.ListenerUuid] = this
	return err
}

func (this *GBListener) postActionListenerServiceStop() (ret int, err error) {
	delete(LbListeners, this.lb.ListenerUuid)
	if e, _ := utils.PathExists(this.pidPath); e {
		err = os.Remove(this.pidPath)
		utils.LogError(err)
	}
	if e, _ := utils.PathExists(this.confPath); e {
		err = os.Remove(this.confPath)
		utils.LogError(err)
	}

	return 0, err
}

func setPidRLimit(confpath string) error {
	if pid, err := utils.FindFirstPIDByPS(confpath); pid > 0 {
		bash := utils.Bash{
			Command: fmt.Sprintf("sudo cat /proc/%d/limits | grep 'Max open files' | awk -F ' ' '{print $5}' ", pid),
		}

		_, hlimit, _, er := bash.RunWithReturn()
		if er != nil {
			log.Debugf("cat not get pid %d hard limit", pid)
			return er
		}
		hlimit = strings.Replace(hlimit, "\n", "", -1)
		bash = utils.Bash{
			Command: fmt.Sprintf("sudo /opt/vyatta/sbin/goprlimit -p %d -s %s",
				pid, hlimit),
		}

		ret, out, _, e := bash.RunWithReturn()
		log.Debugf("%d %s", ret, out)
		if e != nil {
			return e
		}

		return nil
	} else {
		return err
	}
}

func startGobetween(confpath, pidpath string) (int, error) {
	goBetweenPath := "/opt/vyatta/sbin/gobetween"
	if utils.IsEuler2203() {
		goBetweenPath = "/usr/local/bin/gobetween"
	}
	bash := utils.Bash{
		Command: fmt.Sprintf("%s -c %s >/dev/null 2>&1&echo $! >%s; cat %s", goBetweenPath, confpath, pidpath, pidpath),
		Sudo:    true,
	}

	ret, out, _, err := bash.RunWithReturn()
	log.Debugf("%d %s", ret, out)
	if ret != 0 || err != nil {
		log.Debugf("start gobetween faild: ret: %d, err: %v, %s", ret, err, out)
		return ret, err
	}

	if runtime.GOARCH == "amd64" {
		setPidRLimit(confpath)
	}

	return 0, nil
}

func (this *GBListener) startPidMonitor() {
	if _, ok := gobetweenListeners[this.lb.ListenerUuid]; !ok {
		if pid, err := utils.FindFirstPIDByPS(this.confPath); pid > 0 {
			this.pm = utils.NewPidMon(pid, func() int {
				log.Warnf("start gobetween in PidMon for %s", this.lb.ListenerUuid)
				_, err := startGobetween(this.confPath, this.pidPath)
				if err != nil {
					log.Warnf("failed to respawn gobetween: %s", err)
					return -1
				}

				pid, err := utils.FindFirstPIDByPS(this.confPath)
				if err != nil {
					log.Warnf("failed to read gobetween pid: %s", err)
					return -1
				}

				return pid
			})
			log.Debugf("created gobetween PidMon for %s", this.lb.ListenerUuid)
			gobetweenListeners[this.lb.ListenerUuid] = this
			this.pm.Start()
		} else {
			log.Warnf("failed to get gobetween pid: %s", err)
			return
		}
	} else {
		log.Debugf("gobetween PidMon for %s already created", this.lb.ListenerUuid)
	}
}

func (this *GBListener) stopPidMonitor() {
	if lb, ok := gobetweenListeners[this.lb.ListenerUuid]; ok {
		log.Warnf("stop gobetween PidMon for %s", this.lb.ListenerUuid)
		lb.pm.Stop()
		delete(gobetweenListeners, this.lb.ListenerUuid)
	} else {
		log.Warnf("gobetween PidMon for %s not created", this.lb.ListenerUuid)
	}
}

func (this *GBListener) startListenerService() (int, error) {
	var (
		udpAddr *net.UDPAddr
		udpConn *net.UDPConn
		err     error
	)

	if udpAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", this.lb.Vip, this.lb.LoadBalancerPort)); err != nil {
		log.Debugf("ResolveUDPAddr failed %v", err)
		return 0, err
	}

	if udpConn, err = net.ListenUDP("udp", udpAddr); err != nil {
		log.Debugf("ListenUDP failed %v", err)
		return 0, err
	}
	udpConn.Close()

	return startGobetween(this.confPath, this.pidPath)
}

/*get the md5 vaule of a file, return null string if the file not exist */
func getFileChecksum(file string) (checksum string, err error) {
	checksum = ""
	if e, _ := utils.PathExists(file); e {

		bash := utils.Bash{
			Command: fmt.Sprintf("md5sum %s |awk '{print $1}'", file),
		}
		ret, out, _, err := bash.RunWithReturn()
		bash.PanicIfError()
		if ret != 0 || err != nil {
			return "", err
		}
		checksum = out
	}

	return checksum, nil
}

func (this *GBListener) checkIfListenerServiceUpdate(origChecksum string, currChecksum string) (bool, error) {
	var err error
	err = nil
	if pid, _ := utils.FindFirstPIDByPS(this.confPath); pid > 0 {
		if strings.EqualFold(origChecksum, currChecksum) {
			return false, nil
		}
		log.Debugf("lb %s pid: %v orig: %v curr: %v", this.confPath, pid, origChecksum, currChecksum)
		err = utils.KillProcess(pid)
	}

	return true, err
}

func (this *GBListener) getIcmpIptablesRule() ([]*utils.IpTableRule, string) {
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic)
	utils.PanicOnError(err)

	rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.LbRuleComment)
	rule.SetDstIp(this.lb.Vip + "/32").SetProto(utils.IPTABLES_PROTO_ICMP)

	return []*utils.IpTableRule{rule}, nicname
}

func (this *GBListener) getSynIptablesRule() (*utils.IpTableRule, string) {
	return nil, ""
}

func (this *GBListener) getIptablesRule() ([]*utils.IpTableRule, string) {
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic)
	utils.PanicOnError(err)
	var rules []*utils.IpTableRule

	rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(utils.LbRuleComment)
	rule.SetDstPort(this.apiPort).SetProto(utils.IPTABLES_PROTO_TCP)
	rules = append(rules, rule)

	rule = utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
	rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(utils.LbRuleComment)
	rule.SetDstIp(this.lb.Vip + "/32").SetDstPort(fmt.Sprintf("%d", this.lb.LoadBalancerPort)).SetProto(utils.IPTABLES_PROTO_UDP)
	rules = append(rules, rule)

	return rules, nicname
}

func (this *GBListener) getLbInfo() (lb LbInfo) {
	lb = this.lb
	return
}

func (this *GBListener) stopListenerService() (err error) {
	//miao zhanyong the udp lb configured by gobetween, there is no pid configure in the shell cmd line
	pid, err := utils.FindFirstPIDByPS(this.confPath)
	//log.Debugf("lb %s pid: %v result:%v", this.confPath, pid, err)
	err = nil

	if pid > 0 {
		err = utils.KillProcess(pid)
		utils.PanicOnError(err)
	} else if pid == -1 {
		err = nil
	}

	return err
}

func (this *GBListener) getLastCounters() *CachedCounters {
	return this.lastCounters
}

func (this *GBListener) getMaxSession() int {
	return this.maxSession
}

func makeLbAclConfFilePath(lb LbInfo) string {
	return filepath.Join(getLbRootPath(), "conf", fmt.Sprintf("listener-%v-acl.cfg", lb.ListenerUuid))
}

func makeLbPidFilePath(lb LbInfo) string {
	pidPath := filepath.Join(getLbRootPath(), "pid", fmt.Sprintf("lb-%s-listener-%s.pid", lb.LbUuid, lb.ListenerUuid))
	fd, _ := utils.CreateFileIfNotExists(pidPath, os.O_WRONLY|os.O_APPEND, 0666)
	fd.Close()
	return pidPath
}

func makeLbConfFilePath(lb LbInfo) string {
	return filepath.Join(getLbRootPath(), "conf", fmt.Sprintf("lb-%v-listener-%v.cfg", lb.LbUuid, lb.ListenerUuid))
}

func makeCertificatePath(certificateUuid string) string {
	return filepath.Join(getLbCertificateRootPath(), fmt.Sprintf("certificate-%s.pem", certificateUuid))
}

func makeLbSocketPath(lb LbInfo) string {
	return filepath.Join(getLbSocketDir(), fmt.Sprintf("%s.sock", lb.ListenerUuid))
}

type RefreshLbCmd struct {
	Lbs              []LbInfo `json:"lbs"`
	EnableHaproxyLog bool     `json:"enableHaproxyLog"`
}

type deleteLbCmd struct {
	Lbs []LbInfo `json:"lbs"`
}

func makeLbFirewallRuleDescription(lb LbInfo) string {
	return fmt.Sprintf("%s-%v-%v", utils.IpvsComment, lb.LbUuid, lb.ListenerUuid)
}

func makeLbFirewallLocalICMPRuleDescription(lb LbInfo) string {
	return fmt.Sprintf("LBICMP-%v", lb.LbUuid)
}

func setLb(lb LbInfo) bool {
	listener := GetListener(lb)
	if listener == nil {
		return false
	}

	checksum, err := getFileChecksum(makeLbConfFilePath(lb))
	if err != nil {
		log.Errorf("get listener checksum fail %v \n", lb.ListenerUuid)
		return false
	}

	err = listener.createListenerServiceConfigure(lb)
	utils.PanicOnError(err)
	newChecksum, err1 := getFileChecksum(makeLbConfFilePath(lb))
	utils.PanicOnError(err1)
	if update, err := listener.checkIfListenerServiceUpdate(checksum, newChecksum); err == nil && !update {
		log.Debugf("no need refresh the listener: %v\n", lb.ListenerUuid)
		listener.startPidMonitor()
		return false
	}
	utils.PanicOnError(err)

	listener.stopPidMonitor()
	if ret, err := listener.startListenerService(); ret != 0 || err != nil {
		log.Errorf("start listener fail %v \n", lb.ListenerUuid)
		utils.PanicOnError(err)
		return false
	}

	listener.startPidMonitor()
	return false
}

func getCertificateList() []string {
	bash := utils.Bash{
		Command: fmt.Sprintf("find %s -name '*.pem'", getLbCertificateRootPath()),
	}

	if ret, res, _, err := bash.RunWithReturn(); ret != 0 || err != nil {
		return nil
	} else {
		return strings.Split(res, "\n")
	}
}

func isCertificateUsed(certificateFile string) bool {
	bash := utils.Bash{
		Command: fmt.Sprintf("grep -r %s %s", certificateFile, getLbConfDir()),
	}

	if ret, res, _, err := bash.RunWithReturn(); ret != 0 || err != nil {
		return false
	} else if res == "" {
		return false
	} else {
		return true
	}
}

func removeUnusedCertificate() {
	files := getCertificateList()
	for _, file := range files {
		if file != "" && !isCertificateUsed(file) {
			err := os.Remove(file)
			utils.LogError(err)
		}
	}
}

type lbLogLevelConf struct {
	Level string `json:"level"`
}

/*
*
emerg - 0
alert - 1
err - 3
warn - 4
notice - 5
info - 6 (default)
debug - 7
*/
func doRefreshLogLevel(level string) {
	lb_log_file, err := ioutil.TempFile(getLbConfDir(), "rsyslog")
	utils.PanicOnError(err)
	conf := fmt.Sprintf(`$ModLoad imudp
$UDPServerRun 514
local1.%s     /var/log/haproxy.log`, strings.ToLower(level))
	_, err = lb_log_file.Write([]byte(conf))
	utils.PanicOnError(err)

	utils.SudoMoveFile(lb_log_file.Name(), "/etc/rsyslog.d/haproxy.conf")
}

func refreshLogLevel(ctx *server.CommandContext) interface{} {
	cmd := &lbLogLevelConf{}
	ctx.GetCommand(cmd)

	doRefreshLogLevel(cmd.Level)

	return nil
}

func addRuleForTcpSyncByVyos(lbs []Listener) error {
	tree := server.NewParserFromShowConfiguration().Tree
	for _, lb := range lbs {
		info := lb.getLbInfo()
		nicname, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)
		// drop SYN packets to make clients to resend, this is for restarting LB without losing packets
		dropRuleDes := fmt.Sprintf("lb-%v-%s-drop", info.LbUuid, info.ListenerUuid)
		if r := tree.FindFirewallRuleByDescription(nicname, "local", dropRuleDes); r == nil {
			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("description %v", dropRuleDes),
				fmt.Sprintf("destination address %v", info.Vip),
				fmt.Sprintf("destination port %v", info.LoadBalancerPort),
				"protocol tcp",
				"tcp flags SYN",
				"action drop",
			)
			tree.AttachFirewallToInterface(nicname, "local")
		}
	}
	tree.Apply(false)

	return nil
}

func addRuleForTcpSyncByIptables(lbs []Listener) error {
	table := utils.NewIpTables(utils.FirewallTable)

	for _, lb := range lbs {
		rule, _ := lb.getSynIptablesRule()
		if rule != nil {
			table.AddIpTableRules([]*utils.IpTableRule{rule})
		}
	}

	return table.Apply()
}

/* add iptables rule: drop tcp sync packet to avoid haproxy refused the new tcp connection */
func addPreRulesForLbs(lbs []Listener) error {
	tcpLbs := []Listener{}
	for _, lb := range lbs {
		if lb.getLbInfo().Mode != "udp" {
			tcpLbs = append(tcpLbs, lb)
		}
	}
	if len(tcpLbs) == 0 {
		return nil
	}

	var err error
	if utils.IsSkipVyosIptables() {
		err = addRuleForTcpSyncByIptables(tcpLbs)
	} else {
		err = addRuleForTcpSyncByVyos(tcpLbs)
	}
	utils.PanicOnError(err)

	return nil
}

func DelRuleForTcpSyncByVyos(lbs []Listener) error {
	tree := server.NewParserFromShowConfiguration().Tree
	for _, lb := range lbs {
		info := lb.getLbInfo()
		nicname, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)

		// drop SYN packets to make clients to resend, this is for restarting LB without losing packets
		dropRuleDes := fmt.Sprintf("lb-%v-%s-drop", info.LbUuid, info.ListenerUuid)
		if r := tree.FindFirewallRuleByDescription(nicname, "local", dropRuleDes); r != nil {
			r.Delete()
		}
	}
	tree.Apply(false)

	return nil
}

func DelRuleForTcpSyncByLinux(lbs []Listener) error {
	table := utils.NewIpTables(utils.FirewallTable)
	for _, lb := range lbs {
		rule, _ := lb.getSynIptablesRule()
		table.RemoveIpTableRule([]*utils.IpTableRule{rule})
	}
	return table.Apply()
}

/* del iptables rule */
func delPreRulesForLbs(lbs []Listener) error {
	var err error
	tcpLbs := []Listener{}
	for _, lb := range lbs {
		if lb.getLbInfo().Mode != "udp" {
			tcpLbs = append(tcpLbs, lb)
		}
	}
	if len(tcpLbs) == 0 {
		return nil
	}

	if utils.IsSkipVyosIptables() {
		err = DelRuleForTcpSyncByLinux(tcpLbs)
	} else {
		err = DelRuleForTcpSyncByVyos(tcpLbs)
	}
	utils.PanicOnError(err)
	return nil
}

func addRuleForTcpListenerByVyos(lbs []Listener) error {
	tree := server.NewParserFromShowConfiguration().Tree

	changed := false
	for _, lb := range lbs {
		info := lb.getLbInfo()
		if info.Mode == "udp" {
			continue
		}

		changed = true
		des := makeLbFirewallRuleDescription(info)
		nicname, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)
		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("destination address %v", info.Vip),
				fmt.Sprintf("destination port %v", info.LoadBalancerPort),
				fmt.Sprintf("protocol tcp"),
				"action accept",
			)
			configureInternalFirewallRule(tree, des, fmt.Sprintf("description %v", des),
				fmt.Sprintf("destination address %v", info.Vip),
				fmt.Sprintf("destination port %v", info.LoadBalancerPort),
				fmt.Sprintf("protocol tcp"),
				"action accept",
			)
		}

		tree.AttachFirewallToInterface(nicname, "local")
	}

	if changed {
		tree.Apply(false)
	}

	return nil
}

func addRuleForTcpListenerByLinux(lbs []Listener) error {
	table := utils.NewIpTables(utils.FirewallTable)

	changed := false
	for _, lb := range lbs {
		info := lb.getLbInfo()
		if info.Mode == "udp" {
			continue
		}

		if info.Vip == "" {
			/* TODO: add ipv6 tables */
			return nil
		}

		changed = true
		rules, _ := lb.getIptablesRule()
		table.AddIpTableRules(rules)

		priNics := utils.GetPrivteInterface()
		for _, priNic := range priNics {
			for _, r := range rules {
				newRule := r.Copy()
				newRule.SetChainName(utils.GetRuleSetName(priNic, utils.RULESET_LOCAL))
				table.AddIpTableRules([]*utils.IpTableRule{newRule})
			}
		}

	}

	if changed {
		return table.Apply()
	}
	return nil
}

func addRuleForUdpListenerByVyos(lbs []Listener) error {
	tree := server.NewParserFromShowConfiguration().Tree

	changed := false
	for _, lb := range lbs {
		info := lb.getLbInfo()
		if info.Mode != "udp" {
			continue
		}

		gbl := lb.(*GBListener)
		changed = true
		des := makeLbFirewallRuleDescription(info)
		nicname, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)
		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
			/*for lb statistics with restful api*/
			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("destination port %v", gbl.apiPort),
				fmt.Sprintf("protocol tcp"),
				"action accept",
			)

			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("destination address %v", info.Vip),
				fmt.Sprintf("destination port %v", info.LoadBalancerPort),
				fmt.Sprintf("protocol udp"),
				"action accept",
			)

			configureInternalFirewallRule(tree, des,
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("destination address %v", info.Vip),
				fmt.Sprintf("destination port %v", info.LoadBalancerPort),
				fmt.Sprintf("protocol udp"),
				"action accept",
			)
		}

		tree.AttachFirewallToInterface(nicname, "local")
	}

	if changed {
		tree.Apply(false)
	}

	return nil
}

func addRuleForUdpListenerByLinux(lbs []Listener) error {
	table := utils.NewIpTables(utils.FirewallTable)

	changed := false
	for _, lb := range lbs {
		info := lb.getLbInfo()
		if info.Mode != "udp" {
			continue
		}

		if info.Vip == "" {
			/* TODO: add ipv6 tables */
			return nil
		}
		changed = true

		rules, _ := lb.getIptablesRule()
		table.AddIpTableRules(rules)

		priNics := utils.GetPrivteInterface()
		for _, priNic := range priNics {
			for _, r := range rules {
				newRule := r.Copy()
				newRule.SetChainName(utils.GetRuleSetName(priNic, utils.RULESET_LOCAL))
				table.AddIpTableRules([]*utils.IpTableRule{newRule})
			}
		}
	}

	if changed {
		return table.Apply()
	}
	return nil
}

func delRuleForTcpListenerByVyos(lbs []Listener) error {
	tree := server.NewParserFromShowConfiguration().Tree

	changed := false
	for _, lb := range lbs {
		info := lb.getLbInfo()
		if info.Mode == "udp" {
			continue
		}

		changed = true
		des := makeLbFirewallRuleDescription(info)
		localICMPDes := makeLbFirewallLocalICMPRuleDescription(info)
		nicname, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)
		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r != nil {
			r.Delete()
		}
		if r := tree.FindFirewallRuleByDescription(nicname, "local", localICMPDes); (r != nil) && (getListenerCountInLB(info) == 0) {
			r.Delete()
		}
		cleanInternalFirewallRule(tree, des)
	}

	if changed {
		tree.Apply(false)
	}

	return nil
}

func delRuleForTcpListenerByLinux(lbs []Listener) error {
	table := utils.NewIpTables(utils.FirewallTable)

	changed := false
	for _, lb := range lbs {
		info := lb.getLbInfo()
		if info.Mode == "udp" {
			continue
		}

		if info.Vip == "" {
			/* TODO: add ipv6 tables */
			return nil
		}

		changed = true
		var rules []*utils.IpTableRule
		nicname, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)

		r, _ := lb.getIptablesRule()
		rules = append(rules, r...)

		rules, _ = lb.getIcmpIptablesRule()
		rules = append(rules, r...)

		var tempRules []*utils.IpTableRule
		priNics := utils.GetPrivteInterface()
		for _, priNic := range priNics {
			if priNic != nicname {
				for _, r := range rules {
					tmp := r.Copy()
					tmp.SetChainName(utils.GetRuleSetName(priNic, utils.RULESET_LOCAL))
					tempRules = append(tempRules, tmp)
				}
			}
		}
		if len(tempRules) > 0 {
			rules = append(rules, tempRules...)
		}

		table.RemoveIpTableRule(rules)
	}

	if changed {
		return table.Apply()
	} else {
		return nil
	}
}

func delRuleForUdpListenerByVyos(lbs []Listener) error {
	tree := server.NewParserFromShowConfiguration().Tree

	changed := false
	for _, lb := range lbs {
		info := lb.getLbInfo()
		if info.Mode != "udp" {
			continue
		}

		changed = true
		nicname, err := utils.GetNicNameByMac(info.PublicNic)
		utils.PanicOnError(err)

		firewallDes := makeLbFirewallRuleDescription(info)
		localICMPDes := makeLbFirewallLocalICMPRuleDescription(info)

		r := tree.FindFirewallRuleByDescription(nicname, "local", firewallDes)
		for r != nil {
			r.Delete()
			r = tree.FindFirewallRuleByDescription(nicname, "local", firewallDes)
		}
		if r := tree.FindFirewallRuleByDescription(nicname, "local", localICMPDes); (r != nil) && (getListenerCountInLB(info) == 0) {
			r.Delete()
		}
		cleanInternalFirewallRule(tree, firewallDes)
	}

	if changed {
		tree.Apply(false)
	}

	return nil
}

func delRuleForUdpListenerByLinux(lbs []Listener) error {
	table := utils.NewIpTables(utils.FirewallTable)

	changed := false
	for _, lb := range lbs {
		info := lb.getLbInfo()
		if info.Mode != "udp" {
			continue
		}

		if info.Vip == "" {
			/* TODO: add ipv6 tables */
			return nil
		}

		changed = true
		rules, _ := lb.getIptablesRule()
		table.RemoveIpTableRule(rules)

		priNics := utils.GetPrivteInterface()
		for _, priNic := range priNics {
			for _, r := range rules {
				newRule := r.Copy()
				newRule.SetChainName(utils.GetRuleSetName(priNic, utils.RULESET_LOCAL))
				table.RemoveIpTableRule([]*utils.IpTableRule{newRule})
			}
		}

		rules, _ = lb.getIcmpIptablesRule()
		table.RemoveIpTableRule(rules)
	}

	if changed {
		return table.Apply()
	}

	return nil
}

func addLbRules(lbs []Listener) error {

	if utils.IsSkipVyosIptables() {
		err := addRuleForTcpListenerByLinux(lbs)
		utils.PanicOnError(err)
		err = addRuleForUdpListenerByLinux(lbs)
		utils.PanicOnError(err)
	} else {
		err := addRuleForTcpListenerByVyos(lbs)
		utils.PanicOnError(err)
		err = addRuleForUdpListenerByVyos(lbs)
		utils.PanicOnError(err)
	}

	return nil
}

func AddLbs(lbs []Listener) error {
	addPreRulesForLbs(lbs)
	defer delPreRulesForLbs(lbs)

	for _, lb := range lbs {
		setLb(lb.getLbInfo())
	}

	addLbRules(lbs)
	return nil
}

func isIpvsListener(info LbInfo) bool {
	if info.Mode != LB_MODE_UDP {
		return false
	}

	confPath := makeLbConfFilePath(info)
	_, err := utils.FindFirstPIDByPSExtern(true, confPath)
	if err == nil {
		// gobetween is running for listener
		return false
	}

	return true
}

func RefreshLbInternal(cmd *RefreshLbCmd) {
	var toDeleted []Listener
	var toAdded []Listener
	ipvsAdded := map[string]LbInfo{}

	EnableHaproxyLog = cmd.EnableHaproxyLog
	for _, lb := range cmd.Lbs {
		if isIpvsListener(lb) {
			ipvsAdded[lb.ListenerUuid] = lb
			continue
		}

		listener := GetListener(lb)
		if listener == nil {
			continue
		}

		if len(lb.NicIps) == 0 {
			toDeleted = append(toDeleted, listener)
		} else if lb.Mode == LB_MODE_HTTPS && lb.CertificateUuid == "" {
			toDeleted = append(toDeleted, listener)
		} else {
			toAdded = append(toAdded, listener)
		}
	}

	if len(toDeleted) != 0 {
		delLbs(toDeleted)
	}

	if len(toAdded) != 0 {
		AddLbs(toAdded)
	}

	if len(ipvsAdded) > 0 {
		RefreshIpvsService(ipvsAdded, cmd.EnableHaproxyLog)
	}

}

func refreshLb(ctx *server.CommandContext) interface{} {
	cmd := &RefreshLbCmd{}
	ctx.GetCommand(cmd)
	RefreshLbInternal(cmd)

	removeUnusedCertificate()
	return nil
}

func delLbs(lbs []Listener) error {
	for _, lb := range lbs {
		lb.stopPidMonitor()
		err := lb.stopListenerService()
		utils.PanicOnError(err)
	}

	if utils.IsSkipVyosIptables() {
		err := delRuleForTcpListenerByLinux(lbs)
		utils.PanicOnError(err)
		err = delRuleForUdpListenerByLinux(lbs)
		utils.PanicOnError(err)
	} else {
		err := delRuleForTcpListenerByVyos(lbs)
		utils.PanicOnError(err)
		err = delRuleForUdpListenerByVyos(lbs)
		utils.PanicOnError(err)
	}

	return nil
}

func DeleteLbInternal(cmd *deleteLbCmd) {
	toDeleted := []Listener{}
	ipvs := map[string]LbInfo{}
	if len(cmd.Lbs) > 0 {
		for _, lb := range cmd.Lbs {
			if isIpvsListener(lb) {
				ipvs[lb.ListenerUuid] = lb
				continue
			}

			listener := GetListener(lb)
			if listener == nil {
				continue
			}
			toDeleted = append(toDeleted, listener)
		}
	}

	if len(toDeleted) > 0 {
		delLbs(toDeleted)
	}

	if len(ipvs) >= 0 {
		DelIpvsService(ipvs)
	}
}

func deleteLb(ctx *server.CommandContext) interface{} {
	cmd := &deleteLbCmd{}
	ctx.GetCommand(cmd)

	DeleteLbInternal(cmd)

	removeUnusedCertificate()

	return nil
}

func createCertificateHandler(ctx *server.CommandContext) interface{} {
	certificate := &CertificateInfo{}
	ctx.GetCommand(certificate)

	return createCertificate(certificate.Uuid, []byte(certificate.Certificate))
}

func createCertificatesHandler(ctx *server.CommandContext) interface{} {
	certificates := &certificatesCmd{}
	ctx.GetCommand(certificates)

	for uuid, cert := range certificates.Certs {
		createCertificate(uuid, []byte(cert))
	}

	return nil
}

func createCertificate(uuid string, certificate []byte) interface{} {
	certificatePath := makeCertificatePath(uuid)
	if e, _ := utils.PathExists(certificatePath); e {
		/* certificate create api may be called multiple times */
		return nil
	}

	err := utils.MkdirForFile(certificatePath, 0755)
	utils.PanicOnError(err)
	err = os.WriteFile(certificatePath, certificate, 0755)
	utils.PanicOnError(err)

	return nil
}

func deleteCertificateHandler(ctx *server.CommandContext) interface{} {
	cmd := &deleteCertificateCmd{}
	ctx.GetCommand(cmd)

	return deleteCertificate(cmd)
}

func deleteCertificate(cmd *deleteCertificateCmd) interface{} {
	certificatePath := makeCertificatePath(cmd.Uuid)
	if e, _ := utils.PathExists(certificatePath); !e {
		return nil
	}

	if err := utils.DeleteFile(certificatePath); err != nil {
		return err
	}

	return nil
}

type loadBalancerCollector struct {
	statusEntry                 *prom.Desc
	inByteEntry                 *prom.Desc
	outByteEntry                *prom.Desc
	curSessionNumEntry          *prom.Desc
	refusedSessionNumEntry      *prom.Desc
	totalSessionNumEntry        *prom.Desc
	curSessionUsageEntry        *prom.Desc
	concurrentSessionUsageEntry *prom.Desc
	// just for l7 layer lb
	hrsp1xxEntry   *prom.Desc
	hrsp2xxEntry   *prom.Desc
	hrsp3xxEntry   *prom.Desc
	hrsp4xxEntry   *prom.Desc
	hrsp5xxEntry   *prom.Desc
	hrspOtherEntry *prom.Desc
}

const (
	LB_UUID                = "LbUuid"
	LB_LISTENER_UUID       = "ListenerUuid"
	LB_LISTENER_BACKEND_IP = "NicIpAddress"
)

func NewLbPrometheusCollector() MetricCollector {
	return &loadBalancerCollector{
		statusEntry: prom.NewDesc(
			"zstack_lb_status",
			"Backend server health status",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		curSessionNumEntry: prom.NewDesc(
			"zstack_lb_cur_session_num",
			"Backend server active session number",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		inByteEntry: prom.NewDesc(
			"zstack_lb_in_bytes",
			"Backend server traffic in bytes",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		outByteEntry: prom.NewDesc(
			"zstack_lb_out_bytes",
			"Backend server traffic in bytes",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		curSessionUsageEntry: prom.NewDesc(
			"zstack_lb_cur_session_usage",
			"Backend server active session ratio of max session",
			[]string{LB_LISTENER_UUID, LB_UUID}, nil,
		),

		refusedSessionNumEntry: prom.NewDesc(
			"zstack_lb_refused_session_num",
			"Backend server refused session number",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		totalSessionNumEntry: prom.NewDesc(
			"zstack_lb_total_session_num",
			"Backend server total session number",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		concurrentSessionUsageEntry: prom.NewDesc(
			"zstack_lb_concurrent_session_num",
			"Backend server session number including active and waiting state session",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		hrsp1xxEntry: prom.NewDesc(
			"zstack_lb_hrsp1xx",
			"Backend server http response general status 1xx which means informational message to be skipped",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		hrsp2xxEntry: prom.NewDesc(
			"zstack_lb_hrsp2xx",
			"Backend server http response general status 2xx which means OK, content is following",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		hrsp3xxEntry: prom.NewDesc(
			"zstack_lb_hrsp3xx",
			"Backend server http response general status 3xx which means OK, no content following",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		hrsp4xxEntry: prom.NewDesc(
			"zstack_lb_hrsp4xx",
			"Backend server http response general status 4xx which means error caused by the client",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		hrsp5xxEntry: prom.NewDesc(
			"zstack_lb_hrsp5xx",
			"Backend server http response general status 5xx which means error caused by the server",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		hrspOtherEntry: prom.NewDesc(
			"zstack_lb_hrspOther",
			"Backend server other http response",
			[]string{LB_LISTENER_UUID, LB_LISTENER_BACKEND_IP, LB_UUID}, nil,
		),
		//vipUUIds: make(map[string]string),
	}
}

func (c *loadBalancerCollector) Describe(ch chan<- *prom.Desc) error {
	ch <- c.statusEntry
	ch <- c.curSessionNumEntry
	ch <- c.inByteEntry
	ch <- c.outByteEntry
	ch <- c.curSessionUsageEntry
	ch <- c.refusedSessionNumEntry
	ch <- c.totalSessionNumEntry
	ch <- c.concurrentSessionUsageEntry
	ch <- c.hrsp1xxEntry
	ch <- c.hrsp2xxEntry
	ch <- c.hrsp3xxEntry
	ch <- c.hrsp4xxEntry
	ch <- c.hrsp5xxEntry
	ch <- c.hrspOtherEntry
	return nil
}

func TransformToMetric(c *loadBalancerCollector, listenerUuid string, listener Listener, ch chan<- prom.Metric) {
	var counters []*LbCounter
	num := 0

	var maxSessionNum, sessionNum uint64
	sessionNum = 0
	lbUuid := ""

	lbUuid = listener.getLbInfo().LbUuid
	counters = listener.getLastCounters().counters
	num = len(counters)
	maxSessionNum = (uint64)(listener.getMaxSession())
	/* get total count */
	for _, cnt := range counters {
		sessionNum += cnt.sessionNumber
	}

	for i := 0; i < num; i++ {
		cnt := counters[i]
		ch <- prom.MustNewConstMetric(c.statusEntry, prom.GaugeValue, float64(cnt.Status), cnt.listenerUuid, cnt.ip, lbUuid)
		ch <- prom.MustNewConstMetric(c.inByteEntry, prom.GaugeValue, float64(cnt.bytesIn), cnt.listenerUuid, cnt.ip, lbUuid)
		ch <- prom.MustNewConstMetric(c.outByteEntry, prom.GaugeValue, float64(cnt.bytesOut), cnt.listenerUuid, cnt.ip, lbUuid)
		ch <- prom.MustNewConstMetric(c.curSessionNumEntry, prom.GaugeValue, float64(cnt.sessionNumber), cnt.listenerUuid, cnt.ip, lbUuid)
		ch <- prom.MustNewConstMetric(c.refusedSessionNumEntry, prom.GaugeValue, float64(cnt.refusedSessionNumber), cnt.listenerUuid, cnt.ip, lbUuid)
		ch <- prom.MustNewConstMetric(c.totalSessionNumEntry, prom.GaugeValue, float64(cnt.totalSessionNumber), cnt.listenerUuid, cnt.ip, lbUuid)
		ch <- prom.MustNewConstMetric(c.concurrentSessionUsageEntry, prom.GaugeValue, float64(cnt.concurrentSessionNumber), cnt.listenerUuid, cnt.ip, lbUuid)
	}

	ch <- prom.MustNewConstMetric(c.curSessionUsageEntry, prom.GaugeValue, float64(sessionNum*100/maxSessionNum), listenerUuid, lbUuid)

	if _, ok := listener.(*HaproxyListener); ok {
		for i := 0; i < num; i++ {
			cnt := counters[i]
			ch <- prom.MustNewConstMetric(c.hrsp1xxEntry, prom.GaugeValue, float64(cnt.hrsp1xx), cnt.listenerUuid, cnt.ip, lbUuid)
			ch <- prom.MustNewConstMetric(c.hrsp2xxEntry, prom.GaugeValue, float64(cnt.hrsp2xx), cnt.listenerUuid, cnt.ip, lbUuid)
			ch <- prom.MustNewConstMetric(c.hrsp3xxEntry, prom.GaugeValue, float64(cnt.hrsp3xx), cnt.listenerUuid, cnt.ip, lbUuid)
			ch <- prom.MustNewConstMetric(c.hrsp4xxEntry, prom.GaugeValue, float64(cnt.hrsp4xx), cnt.listenerUuid, cnt.ip, lbUuid)
			ch <- prom.MustNewConstMetric(c.hrsp5xxEntry, prom.GaugeValue, float64(cnt.hrsp5xx), cnt.listenerUuid, cnt.ip, lbUuid)
			ch <- prom.MustNewConstMetric(c.hrspOtherEntry, prom.GaugeValue, float64(cnt.hrspOther), cnt.listenerUuid, cnt.ip, lbUuid)
		}
	}
}

func (c *loadBalancerCollector) Update(metricCh chan<- prom.Metric) error {
	if !IsMaster() {
		return nil
	}

	UpdateIpvsMetrics(c, metricCh)

	//start goroutine to get data on demand
	//case 1. The last launched goroutine has received the data and written to the ch and closed the ch.
	//        action: read the data from ch, push it to cache, start new goroutine
	//case 2. The last launched goroutine timeout and closed the ch
	//        action: start new goroutine
	//case 3. The last launched goroutine is still running, ch is opened
	//		  action: do nothing(not block)
	//case 4. The last launched goroutine has been fully processed last time, the data has been read last time,
	//        and the corresponding ch variable has been set to nil
	//		  action: start new goroutine
	//case 5. this func is called first, the corresponding ch variable is initialized as nil
	//		  action: start new goroutine
	for listenerUuid, listener := range LbListeners {
		if listener.getLastCounters().ch != nil {
			select {
			case data, ok := <-listener.getLastCounters().ch:
				if ok { // case 1
					listener.getLastCounters().counters = data.counters
					listener.getLastCounters().ch = listener.getLbCounters(listenerUuid, listener)
				} else { // case 2
					listener.getLastCounters().ch = listener.getLbCounters(listenerUuid, listener)
				}
			default: //case 3
			}
		} else { // case 4 and case 5
			listener.getLastCounters().ch = listener.getLbCounters(listenerUuid, listener)
		}
	}

	//try to read and use the data if there is data in the corresponding ch
	copiedListeners := make(map[string]Listener, len(LbListeners))
	for key, value := range LbListeners {
		copiedListeners[key] = value
	}
	attempts := 0
	maxAttempts := 3
	for len(copiedListeners) > 0 && attempts < maxAttempts {
		attempts++
		for listenerUuid, listener := range copiedListeners {
			if listener.getLastCounters().ch != nil {
				select {
				case data, ok := <-listener.getLastCounters().ch:
					if ok {
						listener.getLastCounters().counters = data.counters
						TransformToMetric(c, listenerUuid, listener, metricCh)
						delete(copiedListeners, listenerUuid)
						listener.getLastCounters().ch = nil
						//log.Debugf("use new counters: %s", listenerUuid)
					}
				default:
					//do nothing
				}
			}
		}
		time.Sleep(time.Duration(1) * time.Second)
	}

	//if there is still goroutines running(not finished), use last cached data
	for listenerUuid, listener := range copiedListeners {
		if listener.getLastCounters().counters != nil {
			//log.Debugf("use last cached counters: %s", listenerUuid)
			TransformToMetric(c, listenerUuid, listener, metricCh)
		}
	}

	return nil
}

type LbCounter struct {
	lbUuid                  string
	listenerUuid            string
	ip                      string
	Status                  uint64
	bytesIn                 uint64
	bytesOut                uint64
	sessionNumber           uint64
	refusedSessionNumber    uint64
	totalSessionNumber      uint64
	concurrentSessionNumber uint64
	// just for l7 layer lb
	hrsp1xx   uint64
	hrsp2xx   uint64
	hrsp3xx   uint64
	hrsp4xx   uint64
	hrsp5xx   uint64
	hrspOther uint64
}

func getIpFromLbStat(name string) string {
	res := strings.Split(name, "-")
	return res[1]
}

func statusFormat(status string) int {
	switch status {
	case "UP":
		return 1
	/*case "DOWN":
	return 0*/
	default:
		return 0
	}
}

func (this *HaproxyListener) getLbCounters(listenerUuid string, listener Listener) <-chan CounterChanData {
	ch := make(chan CounterChanData)
	go func() {
		//log.Debugf("getLbCounters gorotine start: %s", listenerUuid)
		defer func() { close(ch) }()
		var counters []*LbCounter
		num := 0

		client := &haproxy.HAProxyClient{
			Addr:    "unix://" + this.sockPath,
			Timeout: 5 * 60,
		}

		stats, err := client.Stats()
		if err != nil {
			log.Infof("client.Stats failed %v", err)
		}

		for _, stat := range stats {
			if m, err := regexp.MatchString(LB_BACKEND_PREFIX_REG, stat.SvName); err != nil || !m {
				continue
			}

			counter := LbCounter{}
			counter.listenerUuid = listenerUuid
			counter.lbUuid = listener.getLbInfo().LbUuid
			counter.ip = getIpFromLbStat(stat.SvName)
			counter.Status = (uint64)(statusFormat(stat.Status))
			counter.bytesIn = stat.Bin
			counter.bytesOut = stat.Bout
			counter.sessionNumber = stat.Scur
			counter.refusedSessionNumber = stat.Dreq
			counter.concurrentSessionNumber = stat.Scur + stat.Qcur
			counter.totalSessionNumber = stat.Stot
			counter.hrsp1xx = stat.Hrsp1xx
			counter.hrsp2xx = stat.Hrsp2xx
			counter.hrsp3xx = stat.Hrsp3xx
			counter.hrsp4xx = stat.Hrsp4xx
			counter.hrsp5xx = stat.Hrsp5xx
			counter.hrspOther = stat.HrspOther
			counters = append(counters, &counter)
			num++
		}

		if len(counters) > 0 {
			ch <- CounterChanData{
				counters: counters,
			}
		}
		//log.Debugf("getLbCounters gorotine end: %s", listenerUuid)
	}()
	return ch
}

type GoBetweenServerBackendStat struct {
	Live                bool   `json:"live"`
	Active_connections  uint64 `json:"active_connections"`
	Total_connections   uint64 `json:"total_connections"`
	Refused_connections uint64 `json:"refused_connections"`
	Rx                  uint64 `json:"rx"`
	Tx                  uint64 `json:"tx"`
}

type GoBetweenServerBackend struct {
	Host  string                     `json:"host"`
	Stats GoBetweenServerBackendStat `json:"stats"`
}

type GoBetweenServerStat struct {
	Active_connections uint64                   `json:"active_connections"`
	Backends           []GoBetweenServerBackend `json:"backends"`
}

/* map to store: <listenerUuid, GBListerner> pair or  or <listenerUuid, HaProxyListener> */
var LbListeners map[string]Listener
var goBetweenClient = &http.Client{
	Timeout: time.Second * 5,
}

func getListenerCountInLB(lb LbInfo) (counter int) {
	counter = 0
	for _, listener := range LbListeners {
		var lbtmp LbInfo
		switch v := listener.(type) {
		case *HaproxyListener:
			lbtmp = v.getLbInfo()
			break
		case *GBListener:
			lbtmp = v.getLbInfo()
			break
		default:
			continue
		}
		if lb.LbUuid == lbtmp.LbUuid {
			counter++
		}
	}
	log.Debugf("lb-%s contains %d listener", lb.LbUuid, counter)
	return
}

func getGoBetweenStat(port string, server string) (*GoBetweenServerStat, error) {
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

func (this *GBListener) getLbCounters(listenerUuid string, listener Listener) <-chan CounterChanData {
	ch := make(chan CounterChanData)
	go func() {
		defer func() { close(ch) }()

		var counters []*LbCounter
		var stats *GoBetweenServerStat
		var err error
		num := 0

		port := this.apiPort
		if stats, err = getGoBetweenStat(port, listenerUuid); err != nil {
			log.Debugf("get getGoBetweenStat stats failed because %+v", err)
		}

		for _, stat := range stats.Backends {
			counter := LbCounter{}
			counter.listenerUuid = listenerUuid
			counter.lbUuid = listener.getLbInfo().LbUuid
			counter.ip = stat.Host
			if stat.Stats.Live {
				counter.Status = 1
			} else {
				counter.Status = 0
			}
			counter.bytesIn = stat.Stats.Tx //the direction of LB is different from backend direction
			counter.bytesOut = stat.Stats.Rx
			counter.sessionNumber = stat.Stats.Active_connections
			counter.refusedSessionNumber = stat.Stats.Refused_connections
			counter.totalSessionNumber = stat.Stats.Total_connections
			counter.concurrentSessionNumber = stat.Stats.Active_connections
			counters = append(counters, &counter)
			num++
		}
		if len(counters) > 0 {
			ch <- CounterChanData{
				counters: counters,
			}
		}
	}()
	return ch
}

func InitLb() {
	os.Mkdir(getLbRootPath(), os.ModePerm)
	os.Mkdir(getLbConfDir(), os.ModePerm)
	os.Mkdir(getLbPidDir(), os.ModePerm)
	os.Chmod(getLbPidDir(), os.ModePerm)
	os.Mkdir(getLbSocketDir(), os.ModePerm|os.ModeSocket)
	LbListeners = make(map[string]Listener, LISTENER_MAP_SIZE)
	RegisterPrometheusCollector(NewLbPrometheusCollector())

	bash := utils.Bash{
		/* for vyos 1.1.7, it return "2.1.0 "
		   for openEuler 22.03, it return "2.6.6-274d1a4 "
		*/
		Command: fmt.Sprintf(getHaproxyBindPath() + " -ver | grep version | awk '{print $3}'"),
	}

	if ret, out, _, err := bash.RunWithReturn(); ret == 0 && err == nil {
		haproxyVersion = out[:5]
	}

	log.Debug("haproxyVersion :" + haproxyVersion)
	gobetweenListeners = map[string]*GBListener{}
	haproxyListeners = map[string]*HaproxyListener{}
}

func LbEntryPoint() {
	server.RegisterAsyncCommandHandler(REFRESH_LB_PATH, server.VyosLock(refreshLb))
	server.RegisterAsyncCommandHandler(REFRESH_LB_LOG_LEVEL_PATH, server.VyosLock(refreshLogLevel))
	server.RegisterAsyncCommandHandler(DELETE_LB_PATH, server.VyosLock(deleteLb))
	server.RegisterAsyncCommandHandler(CREATE_CERTIFICATE_PATH, server.VyosLock(createCertificateHandler))
	server.RegisterAsyncCommandHandler(DELETE_CERTIFICATE_PATH, server.VyosLock(deleteCertificateHandler))
	server.RegisterAsyncCommandHandler(CREATE_CERTIFICATES_PATH, server.VyosLock(createCertificatesHandler))
}
