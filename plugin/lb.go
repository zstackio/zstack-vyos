package plugin

import (
	"github.com/zstackio/zstack-vyos/server"
	"html/template"
	"github.com/zstackio/zstack-vyos/utils"
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
	cidrman "github.com/EvilSuperstars/go-cidrman"
	"sort"
	log "github.com/Sirupsen/logrus"
	"net/http"
	"time"
	"encoding/json"
	"errors"
	"crypto/md5"
	"runtime"
)

const (
	REFRESH_LB_PATH = "/lb/refresh"
	REFRESH_LB_LOG_LEVEL_PATH = "/lb/log/level"
	DELETE_LB_PATH = "/lb/delete"
	CREATE_CERTIFICATE_PATH = "/certificate/create"
	DELETE_CERTIFICATE_PATH   = "/certificate/delete"
	LB_ROOT_DIR = "/home/vyos/zvr/lb/"
	LB_CONF_DIR = "/home/vyos/zvr/lb/conf/"
	LB_PID_DIR = "/home/vyos/zvr/lb/pid/"
	CERTIFICATE_ROOT_DIR = "/home/vyos/zvr/certificate/"
	LB_SOCKET_DIR = "/home/vyos/zvr/lb/sock/"

	LB_MODE_HTTPS = "https"

	LB_BACKEND_PREFIX_REG = "^nic-"

	LISTENER_MAP_SIZE = 128
	//reserve some sockets for haproxy if specify the parameter "ulimit-n"
	RESERVE_SOCK_COUNT = 100
	MAX_SOCK_COUNT = 20971520

	LB_LOCAL_ICMP_FIREWALL_RULE_NUMBER = 2000
	HAPROXY_VERSION_1_6_9 = "1.6.9"
	HAPROXY_VERSION_2_1_0 = "2.1.0"
)

var (
	haproxyVersion = HAPROXY_VERSION_1_6_9
	gobetweenListeners map[string]*GBListener
)

const (
	TLS_CIPHER_POLICY_DEFAULT = "tls_cipher_policy_default"
	TLS_CIPHER_POLICY_1_0 = "tls_cipher_policy_1_0"
	TLS_CIPHER_POLICY_1_1 = "tls_cipher_policy_1_1"
	TLS_CIPHER_POLICY_1_2 = "tls_cipher_policy_1_2"
	TLS_CIPHER_POLICY_1_2_STRICT = "tls_cipher_policy_1_2_strict"
	TLS_CIPHER_POLICY_1_2_STRICT_WITH_1_3 = "tls_cipher_policy_1_2_strict_with_1_3"

	LBSecurityPolicyConfiguration = `
    ssl-default-bind-ciphers %s
    ssl-default-bind-options %s
	`
)

const(
	LBSecurityPolicyCommonCiphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA"
	LBSecurityPolicy1_2_3CommonCiphers = "AES128-GCM-SHA256:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"
	LBSecurityPolicystrict3OnlyCiphers = "TLS_AES_256_GCM_SHA384:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA"
)

type backendServerInfo struct{
	Ip string `json:"ip"`
	Weight int `json:"weight`
}

type serverGroupInfo struct {
	Name string `json:"name"`
	ServerGroupUuid string `json:"serverGroupUuid"`
	BackendServers []backendServerInfo `json:"backendServers"`
	IsDefault bool `json:"isDefault"`
}

type redirectRuleInfo struct {
	RedirectRuleUuid string `json:"redirectRuleUuid"`
	AclUuid string `json:"aclUuid"`
	RedirectRule string `json:"redirectRule"`
	ServerGroupUuid string `json:"serverGroupUuid"`
}

type lbInfo struct {
	LbUuid             string   `json:"lbUuid"`
	ListenerUuid       string   `json:"listenerUuid"`
	Vip                string   `json:"vip"`
	PublicNic          string   `json:"publicNic"`
	NicIps             []string `json:"nicIps"`
	InstancePort       int      `json:"instancePort"`
	LoadBalancerPort   int      `json:"loadBalancerPort"`
	Mode               string   `json:"mode"`
	Parameters         []string `json:"parameters"`
	CertificateUuid    string   `json:"certificateUuid"`
	SecurityPolicyType string   `json:"securityPolicyType"`
	ServerGroups       []serverGroupInfo `json:"serverGroups"`
	RedirectRules      []redirectRuleInfo `json:"redirectRules"`
}


type certificateInfo struct {
	Uuid string `json:"uuid"`
	Certificate string `json:"certificate"`
}

type deleteCertificateCmd struct {
	Uuid string `json:"uuid"`
}

type Listener interface {
	createListenerServiceConfigure(lb lbInfo)  ( err error)
	checkIfListenerServiceUpdate(origChecksum string, currChecksum string) ( bool, error)
	preActionListenerServiceStart() ( err error)
	rollbackPreActionListenerServiceStart() ( err error)
	startListenerService() (ret int, err error)
	postActionListenerServiceStart() ( err error)
	stopListenerService() ( err error)
	postActionListenerServiceStop() (ret int, err error)
	getLbCounters(listenerUuid string) ([]*LbCounter, int)
	getIptablesRule()([]utils.IptablesRule, string)
	getLbInfo() (lb lbInfo)
}

// the listener implemented with HaProxy
type HaproxyListener struct {
	lb lbInfo
	confPath string
	pidPath	string
	sockPath string
	firewallDes string
	firewallLocalICMPDes string
	maxConnect string
	maxSession int   //same to maxConnect
	aclPath string
}

// the listener implemented with gobetween
type GBListener struct {
	lb lbInfo
	confPath string
	pidPath	string
	firewallDes string
	firewallLocalICMPDes string
	apiPort string // restapi binding port range from 50000-60000
	maxConnect string
	maxSession int   //same to maxConnect
	aclPath string
	pm      *utils.PidMon
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
		return &GBListener{lb:lb, confPath: confPath, pidPath:pidPath, firewallDes:des, firewallLocalICMPDes:localICMPDes, apiPort:port, aclPath:aclPath}
	case "tcp", "https", "http":
		return &HaproxyListener{lb:lb, confPath: confPath, pidPath:pidPath, firewallDes:des, firewallLocalICMPDes:localICMPDes, sockPath:sockPath, aclPath:aclPath}
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
			o, err := cidrman.IPRangeToCIDRs(ips[0], ips[1]); utils.PanicOnError(err)
			entry = append(entry, o...)
		} else {
			entry = append(entry, e)
		}
	}

	return entry
}

func parseListenerPrameter(lb lbInfo) (map[string]interface{}, error) {
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
				code := map[string]string{"http_2xx":"2","http_3xx":"3","http_4xx":"4","http_5xx":"5",}
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

	if lb.SecurityPolicyType == TLS_CIPHER_POLICY_1_0{
		m["SecurityOptions"] = fmt.Sprintf(LBSecurityPolicyConfiguration, LBSecurityPolicyCommonCiphers+":"+LBSecurityPolicy1_2_3CommonCiphers, "no-sslv3 no-tlsv13 no-tls-tickets")
	} else if lb.SecurityPolicyType == TLS_CIPHER_POLICY_1_1{
		m["SecurityOptions"] =  fmt.Sprintf(LBSecurityPolicyConfiguration, LBSecurityPolicyCommonCiphers+":"+LBSecurityPolicy1_2_3CommonCiphers,"no-sslv3 no-tlsv10 no-tlsv13 no-tls-tickets")
	} else if lb.SecurityPolicyType == TLS_CIPHER_POLICY_1_2{
		m["SecurityOptions"] =  fmt.Sprintf(LBSecurityPolicyConfiguration, LBSecurityPolicyCommonCiphers+":"+LBSecurityPolicy1_2_3CommonCiphers,"no-sslv3 no-tlsv10 no-tlsv11 no-tlsv13 no-tls-tickets")
	} else if lb.SecurityPolicyType == TLS_CIPHER_POLICY_1_2_STRICT{
		m["SecurityOptions"] =  fmt.Sprintf(LBSecurityPolicyConfiguration, LBSecurityPolicyCommonCiphers,"no-sslv3 no-tlsv10 no-tlsv11 no-tlsv13 no-tls-tickets")
	} else if lb.SecurityPolicyType == TLS_CIPHER_POLICY_1_2_STRICT_WITH_1_3{
		m["SecurityOptions"] =  fmt.Sprintf(LBSecurityPolicyConfiguration, LBSecurityPolicyCommonCiphers+":"+LBSecurityPolicystrict3OnlyCiphers,"no-sslv3 no-tlsv10 no-tlsv11 no-tlsv12 no-tls-tickets")
	}

	m["CertificatePath"] = makeCertificatePath(lb.CertificateUuid)
	m["SocketPath"] = makeLbSocketPath(lb)
	m["Weight"] = weight

	var combinedServerGroups []serverGroupInfo
	var isAclRedirect bool
	var defaultServerGroup serverGroupInfo


	if ( lb.RedirectRules != nil ) && (len(lb.RedirectRules) > 0 ) && ( (lb.Mode == "http" ) || (lb.Mode == "https"))  {
		isAclRedirect = true
		m["IsAclRedirect"] = "enable"
	} else {
		m["IsAclRedirect"] = "disable"
	}

	if isAclRedirect {
		m["RedirectRules"] = lb.RedirectRules
		for _, sGroup := range lb.ServerGroups{
			if sGroup.IsDefault {
				defaultServerGroup.BackendServers = append(defaultServerGroup.BackendServers, sGroup.BackendServers...)
			} else {
				combinedServerGroups = append(combinedServerGroups,sGroup)
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
		combinedServerGroups = append(combinedServerGroups,defaultServerGroup)
	} else {
		m["DefaultServerGroupUuid"] = ""
		log.Debugf("defaultServerGroupUuid is null")
	}

	if len(combinedServerGroups) > 0  {
		m["ServerGroups"] = combinedServerGroups
	} else {
		m["ServerGroups"] = []serverGroupInfo{}
	}

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
    #user vyos
    #group users
    uid {{.uid}}
    gid {{.gid}}
    daemon
    #stats socket {{.SocketPath}} user vyos
    stats socket {{.SocketPath}} gid {{.gid}} uid {{.uid}}
    ulimit-n {{.ulimit}}
{{if eq .HaproxyVersion "1.6.9"}}
    nbproc {{.Nbprocess}}
{{else}}
    nbthread {{.Nbprocess}}
{{end}}
	{{.SecurityOptions}}
defaults
    log global
    option dontlognull
{{- if eq .Mode "https" "http"}}
    option {{.HttpMode}}
{{end}}


frontend {{.ListenerUuid}}
{{- if eq .Mode "https"}}
    mode http
{{- else}}
    mode {{.Mode}}
{{- end }}
{{if ne .Mode "tcp"}}
    option forwardfor
{{end}}

{{- if eq .Mode "https"}}
    bind {{.Vip}}:{{.LoadBalancerPort}} ssl crt {{.CertificatePath}}
{{- else }}
    bind {{.Vip}}:{{.LoadBalancerPort}}
{{ end }}
    timeout client {{.ConnectionIdleTimeout}}s


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

{{- if eq $.HealthCheckProtocol "http" }}
    option httpchk {{$.HttpChkMethod}} {{$.HttpChkUri}}
{{- if ne $.HttpChkExpect "http_2xx" }}
    http-check expect rstatus {{$.HttpChkExpect}}
{{- end }}
{{- end }}

{{- with .BackendServers }}
{{- range . }}
{{- if eq $.BalancerAlgorithm "static-rr" }}
    server nic-{{.Ip}} {{.Ip}}:{{$.InstancePort}} weight {{.Weight}} check port {{$.CheckPort}} inter {{$.HealthCheckInterval}}s rise {{$.HealthyThreshold}} fall {{$.UnhealthyThreshold}}
{{- else }}
    server nic-{{.Ip}} {{.Ip}}:{{$.InstancePort}} check port {{$.CheckPort}} inter {{$.HealthCheckInterval}}s rise {{$.HealthyThreshold}} fall {{$.UnhealthyThreshold}}
{{- end }}
{{- end }}
{{- end }}
			
{{- end }}
{{- end }}
`
	var buf, acl_buf bytes.Buffer
	var m map[string]interface{}
	tmpl, err := template.New("conf").Parse(conf); utils.PanicOnError(err)
	m, err = parseListenerPrameter(lb);utils.PanicOnError(err)
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
		m["AclEntryMd5"] =  md5.Sum([]byte(m["AclEntry"].(string)))
	}
	if _, exist := m["Nbprocess"]; !exist {
		m["Nbprocess"] = "1"
	}
	m["HaproxyVersion"] = haproxyVersion

	if mode, exist := m["Mode"]; exist && (mode == "http" || mode == "https")  {
	    if _, exist := m["HttpMode"]; !exist{
	        m["HttpMode"] = "http-server-close"
	    }
	}

	bash := utils.Bash{
		Command: fmt.Sprintf("sudo id -u vyos"),
	}
	_, result, _, _ := bash.RunWithReturn();
	result = strings.Replace(result, "\n", "", -1)
	_, er := strconv.Atoi(result);utils.PanicOnError(er)
	m["uid"] = result

	b := utils.Bash{
		Command: fmt.Sprintf("sudo id -g vyos"),
	}
	_, re, _, _ := b.RunWithReturn();
	re = strings.Replace(re, "\n", "", -1)
	_, e := strconv.Atoi(re);utils.PanicOnError(e)
	m["gid"] = re

	err = utils.MkdirForFile(this.aclPath, 0755); utils.PanicOnError(err)
	acl_buf.WriteString(strings.Join(ipRange2Cidrs(strings.Split(m["AclEntry"].(string), ",")),"\n"))
	err = ioutil.WriteFile(this.aclPath, acl_buf.Bytes(), 0755); utils.PanicOnError(err)
	err = tmpl.Execute(&buf, m); utils.PanicOnError(err)
	err = utils.MkdirForFile(this.pidPath, 0755); utils.PanicOnError(err)
	err = utils.MkdirForFile(this.confPath, 0755); utils.PanicOnError(err)
	err = ioutil.WriteFile(this.confPath, buf.Bytes(), 0755); utils.PanicOnError(err)
	LbListeners[this.lb.ListenerUuid] = this
	return err
}

func (this *HaproxyListener) startListenerService() ( ret int, err error) {
	pids := this.getPids()
	
	var bash utils.Bash
	if len(pids) > 0 {
		bash = utils.Bash{
			Command: fmt.Sprintf("sudo /opt/vyatta/sbin/haproxy -D -N %s -f %s -p %s -sf %s",
				this.maxConnect, this.confPath, this.pidPath, strings.Join(pids, " ")),
		}
	} else {
		bash = utils.Bash{
			Command: fmt.Sprintf("sudo /opt/vyatta/sbin/haproxy -D -N %s -f %s -p %s",
				this.maxConnect, this.confPath, this.pidPath),
		}
	}
	var stderr string
	var stdout string
	ret, stdout, stderr,err = bash.RunWithReturn()
	if err!= nil {
	    return ret, errors.New(fmt.Sprintf("shell failure[command: %v, return code: %v, stdout: %v, stderr: %v", bash.Command, ret, stdout, stderr))
	}
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
	comment := makeDropRuleComments(this.lb)
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic); utils.PanicOnError(err)
	if utils.IsSkipVyosIptables() {
		rule, _ := this.getSynIptablesRule()
		ruleMap := map[string][]utils.IptablesRule{}
		ruleMap[nicname] = rule
		for _, pname := range utils.GetPrivteInterface() {
			ruleMap[pname] = rule
		}
		err := utils.SyncFirewallRule(ruleMap, comment, utils.LOCAL)
		return err
	}

	// drop SYN packets to make clients to resend, this is for restarting LB without losing packets
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
	commet := makeDropRuleComments(this.lb)
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic ); utils.PanicOnError(err)
	if utils.IsSkipVyosIptables() {
		utils.DeleteFirewallRuleByComment(nicname, commet)
		for _, pname := range utils.GetPrivteInterface() {
			utils.DeleteFirewallRuleByComment(pname, commet)
		}
		return nil
	}

	// drop SYN packets to make clients to resend, this is for restarting LB without losing packets
	tree := server.NewParserFromShowConfiguration().Tree

	dropRuleDes := fmt.Sprintf("lb-%v-%s-drop", this.lb.LbUuid, this.lb.ListenerUuid)
	if r := tree.FindFirewallRuleByDescription(nicname, "local", dropRuleDes); r != nil {
		r.Delete()
		tree.Apply(false)
	}
	return nil
}

func configureInternalFirewallRule(tree *server.VyosConfigTree, des string, rules ...string) (err error) {
	/*support to access lb vip from all the private nics */
	err = nil
	if utils.IsSkipVyosIptables() {
		return
	}
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
	if utils.IsSkipVyosIptables() {
		return
	}
	priNics := utils.GetPrivteInterface()
	for _, priNic := range priNics {
		if r := tree.FindFirewallRuleByDescription(priNic, "local", des); r != nil {
			r.Delete()
		}
	}
	return
}

/*
setlb:
*/
func (this *HaproxyListener) postActionListenerServiceStart() ( err error) {
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic ); utils.PanicOnError(err)
	dropComment := makeDropRuleComments(this.lb)
	if utils.IsSkipVyosIptables() {
		utils.DeleteFirewallRuleByComment(nicname, dropComment)
		for _, pname := range utils.GetPrivteInterface() {
			utils.DeleteFirewallRuleByComment(pname, dropComment)
		}
		return nil
	}

	tree := server.NewParserFromShowConfiguration().Tree

	if r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallDes); r == nil {
		tree.SetFirewallOnInterface(nicname, "local",
			fmt.Sprintf("description %v", this.firewallDes),
			fmt.Sprintf("destination address %v", this.lb.Vip),
			fmt.Sprintf("destination port %v", this.lb.LoadBalancerPort),
			fmt.Sprintf("protocol tcp"),
			"action accept",
		)
		configureInternalFirewallRule(tree, this.firewallDes, fmt.Sprintf("description %v", this.firewallDes),
			fmt.Sprintf("destination address %v", this.lb.Vip),
			fmt.Sprintf("destination port %v", this.lb.LoadBalancerPort),
			fmt.Sprintf("protocol tcp"),
			"action accept",
		)
	}

	if r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallLocalICMPDes); r == nil {
		tree.SetFirewallWithRuleNumber(nicname, "local", LB_LOCAL_ICMP_FIREWALL_RULE_NUMBER,
			fmt.Sprintf("destination address %v", this.lb.Vip),
			fmt.Sprintf("description %v", this.firewallLocalICMPDes),
			"protocol icmp",
			"action accept")
	}

	dropRuleDes := fmt.Sprintf("lb-%v-%s-drop", this.lb.LbUuid, this.lb.ListenerUuid)
	if r := tree.FindFirewallRuleByDescription(nicname, "local", dropRuleDes); r != nil {
		r.Delete()
	}

	tree.AttachFirewallToInterface(nicname, "local")
	tree.Apply(false)

	return nil
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

func (this *HaproxyListener) stopListenerService() ( err error) {
	pids := this.getPids()
	if len(pids) > 0 {
		for _, pid := range pids {
			p, err := strconv.Atoi(pid); utils.PanicOnError(err)
			err = utils.KillProcess(p); utils.PanicOnError(err)
		}
	} else {
		err = nil
	}

	t := utils.ConnectionTrackTuple{IsNat:false, IsDst: true, Ip: this.lb.Vip, Protocol: "tcp",
		PortStart: this.lb.LoadBalancerPort, PortEnd: this.lb.LoadBalancerPort}
	t.CleanConnTrackConnection()

	return err
}

func (this *HaproxyListener) postActionListenerServiceStop() (ret int, err error) {
	delete(LbListeners, this.lb.ListenerUuid)

	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic ); utils.PanicOnError(err)
	if ! utils.IsSkipVyosIptables() {
		tree := server.NewParserFromShowConfiguration().Tree
		if r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallDes); r != nil {
			r.Delete()
		}
		if r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallLocalICMPDes); (r != nil) && (getListenerCountInLB(this.lb) == 0) {
			r.Delete()
		}
		cleanInternalFirewallRule(tree, this.firewallDes)
		tree.Apply(false)
	}

	if e, _ := utils.PathExists(this.pidPath); e {
		err = os.Remove(this.pidPath); utils.LogError(err)
	}
	if e, _ := utils.PathExists(this.confPath); e {
		err = os.Remove(this.confPath); utils.LogError(err)
	}
	if e, _ := utils.PathExists(this.sockPath); e {
		err = os.Remove(this.sockPath); utils.LogError(err)
	}

	if e, _ := utils.PathExists(this.aclPath); e {
		err = os.Remove(this.aclPath); utils.LogError(err)
	}

	return 0, err
}

func (this *HaproxyListener) getIptablesRule()([]utils.IptablesRule, string) {
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic ); utils.PanicOnError(err)
	return []utils.IptablesRule{utils.NewLoadBalancerIptablesRule(utils.TCP, this.lb.Vip, this.lb.LoadBalancerPort,
		utils.RETURN, makeLbFirewallRuleComments(this.lb), nil)}, nicname
}

func (this *HaproxyListener) getIcmpIptablesRule()([]utils.IptablesRule, string) {
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic ); utils.PanicOnError(err)
	return []utils.IptablesRule{utils.NewLoadBalancerIptablesRule(utils.ICMP, this.lb.Vip, 0,
		utils.RETURN, makeLbFirewallRuleComments(this.lb), nil)}, nicname
}

func (this *HaproxyListener) getSynIptablesRule()([]utils.IptablesRule, string) {
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic ); utils.PanicOnError(err)
	return []utils.IptablesRule{utils.NewLoadBalancerIptablesRule(utils.TCP, this.lb.Vip, this.lb.LoadBalancerPort,
		utils.DROP, makeDropRuleComments(this.lb), []string{utils.SYN})}, nicname
}

func (this *HaproxyListener) getLbInfo() (lb lbInfo) {
	lb = this.lb
	return
}

func (this *GBListener) adaptListenerParameter(m map[string]interface{}) (map[string]interface{}, error) {
	if strings.EqualFold(m["BalancerAlgorithm"].(string), "weightroundrobin") {
		m["BalancerAlgorithm"] = "weight"
	} else if strings.EqualFold(m["BalancerAlgorithm"].(string), "source") {
		m["BalancerAlgorithm"] = "iphash1"
	}
	return m, nil
}

func (this *GBListener) createListenerServiceConfigure(lb lbInfo)  (err error) {
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

	tmpl, err := template.New("conf").Parse(conf); utils.PanicOnError(err)
	m, err = parseListenerPrameter(lb);utils.PanicOnError(err)
	m, err = this.adaptListenerParameter(m);utils.PanicOnError(err)
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

	err = tmpl.Execute(&buf, m); utils.PanicOnError(err)
	err = utils.MkdirForFile(this.pidPath, 0755); utils.PanicOnError(err)
	err = utils.MkdirForFile(this.confPath, 0755); utils.PanicOnError(err)
	err = ioutil.WriteFile(this.confPath, buf.Bytes(), 0755); utils.PanicOnError(err)
	LbListeners[this.lb.ListenerUuid] = this
	return err
}

func setPidRLimit(confpath string) error {
	if pid, err := utils.FindFirstPIDByPS(confpath); pid > 0 {
		bash := utils.Bash{
			Command: fmt.Sprintf("sudo cat /proc/%d/limits | grep 'Max open files' | awk -F ' ' '{print $5}' ",pid),
		}

		_, hlimit, _, er := bash.RunWithReturn()
		if er != nil{
			log.Debugf("cat not get pid %d hard limit", pid)
			return er
		}
		hlimit = strings.Replace(hlimit, "\n", "", -1)
		bash = utils.Bash{
			Command: fmt.Sprintf("sudo /opt/vyatta/sbin/goprlimit -p %d -s %s",
				pid, hlimit),
		}

		ret, out, _, e := bash.RunWithReturn()
		log.Debugf("%d %s",ret, out)
		if e != nil{
			return e
		}

		return nil
	} else {
		return err
	}
}

func startGobetween(confpath, pidpath string) (int, error) {
	bash := utils.Bash{
		Command: fmt.Sprintf("/opt/vyatta/sbin/gobetween -c %s >/dev/null 2>&1&echo $! >%s; cat %s", confpath, pidpath, pidpath),
		Sudo:    true,
	}

	ret, out, _, err := bash.RunWithReturn()
	log.Debugf("%d %s",ret, out)
	if ret != 0 || err != nil {
		log.Debugf("start gobetween faild: ret: %d, err: %v, %s", ret, err, out)
		return ret, err
	}

	if runtime.GOARCH == "amd64"{
		setPidRLimit(confpath)
	}

	return 0, nil
}

func (this *GBListener) startPidMonitor()  {
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

func (this *GBListener) stopPidMonitor()  {
	if lb, ok := gobetweenListeners[this.lb.ListenerUuid]; ok {
		log.Warnf("stop gobetween PidMon for %s", this.lb.ListenerUuid)
		lb.pm.Stop()
		delete(gobetweenListeners, this.lb.ListenerUuid)
	} else {
		log.Warnf("gobetween PidMon for %s not created", this.lb.ListenerUuid)
	}
}

func (this *GBListener) startListenerService() (int,  error) {
	ret, err := startGobetween(this.confPath, this.pidPath)
	if err != nil || ret != 0{
		return ret, err
	}

	this.startPidMonitor()

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
	var err error
	err = nil
	if pid, _:= utils.FindFirstPIDByPS( this.confPath); pid > 0 {
		if strings.EqualFold(origChecksum, currChecksum) {
			this.startPidMonitor()
			return false, nil
		}
		log.Debugf("lb %s pid: %v orig: %v curr: %v", this.confPath, pid, origChecksum, currChecksum)
		err = utils.KillProcess(pid)
	}

	return true, err
}

func (this *GBListener) preActionListenerServiceStart() ( err error) {
	return nil
}
func (this *GBListener) rollbackPreActionListenerServiceStart() ( err error) {
	return nil
}

func (this *GBListener) setGBListenerRuleByIptables(nic string)  {
	dport, _ := strconv.Atoi(this.apiPort)
	rule := utils.NewLoadBalancerIptablesRule(utils.TCP, "", dport,
		utils.ACCEPT, makeLbFirewallRuleComments(this.lb), nil)
	utils.InsertFireWallRule(nic, rule, utils.LOCAL)

	rule = utils.NewLoadBalancerIptablesRule(utils.UDP, this.lb.Vip, this.lb.LoadBalancerPort,
		utils.ACCEPT, makeLbFirewallRuleComments(this.lb), nil)
	utils.InsertFireWallRule(nic, rule, utils.LOCAL)
}

func (this *GBListener) getIcmpIptablesRule()([]utils.IptablesRule, string) {
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic ); utils.PanicOnError(err)
	return []utils.IptablesRule{utils.NewLoadBalancerIptablesRule(utils.ICMP, this.lb.Vip, 0,
		utils.RETURN, makeLbFirewallRuleComments(this.lb), nil)}, nicname
}

func (this *GBListener) postActionListenerServiceStart() ( err error) {
	if utils.IsSkipVyosIptables() {
		return nil
	}

	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic ); utils.PanicOnError(err)
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

		configureInternalFirewallRule(tree, this.firewallDes,
			fmt.Sprintf("description %v", this.firewallDes),
			fmt.Sprintf("destination address %v", this.lb.Vip),
			fmt.Sprintf("destination port %v", this.lb.LoadBalancerPort),
			fmt.Sprintf("protocol udp"),
			"action accept",
		)
	}

	if r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallLocalICMPDes); r == nil {
		tree.SetFirewallWithRuleNumber(nicname, "local", LB_LOCAL_ICMP_FIREWALL_RULE_NUMBER,
			fmt.Sprintf("description %v", this.firewallLocalICMPDes),
			"protocol icmp",
			"action accept")
	}

	tree.AttachFirewallToInterface(nicname, "local")
	tree.Apply(false)
	return nil
}

func (this *GBListener) getIptablesRule()([]utils.IptablesRule, string) {
	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic ); utils.PanicOnError(err)
	dport, _ := strconv.Atoi(this.apiPort)
	return []utils.IptablesRule {
		utils.NewLoadBalancerIptablesRule(utils.TCP, "", dport, utils.ACCEPT, makeLbFirewallRuleComments(this.lb), nil),
		utils.NewLoadBalancerIptablesRule(utils.UDP, this.lb.Vip, this.lb.LoadBalancerPort, utils.ACCEPT, makeLbFirewallRuleComments(this.lb), nil)},
		nicname
}

func (this *GBListener) getLbInfo() (lb lbInfo) {
	lb = this.lb
	return
}

func (this *GBListener) stopListenerService() ( err error) {
	//miao zhanyong the udp lb configured by gobetween, there is no pid configure in the shell cmd line
	pid, err := utils.FindFirstPIDByPS(this.confPath)
	//log.Debugf("lb %s pid: %v result:%v", this.confPath, pid, err)
	err = nil
	this.stopPidMonitor()

	if pid > 0 {
		err = utils.KillProcess(pid); utils.PanicOnError(err)
	} else if pid == -1 {
		err = nil
	}

	return err
}

func (this *GBListener) postActionListenerServiceStop() (ret int, err error) {
	delete(LbListeners, this.lb.ListenerUuid)

	nicname, err := utils.GetNicNameByMac(this.lb.PublicNic ); utils.PanicOnError(err)
	if !utils.IsSkipVyosIptables() {
		tree := server.NewParserFromShowConfiguration().Tree
		r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallDes)
		for r != nil {
			r.Delete()
			r = tree.FindFirewallRuleByDescription(nicname, "local", this.firewallDes)
		}
		if r := tree.FindFirewallRuleByDescription(nicname, "local", this.firewallLocalICMPDes); (r != nil) && (getListenerCountInLB(this.lb) == 0) {
			r.Delete()
		}
		cleanInternalFirewallRule(tree, this.firewallDes)
		tree.Apply(false)
	}

	if e, _ := utils.PathExists(this.pidPath); e {
		err = os.Remove(this.pidPath); utils.LogError(err)
	}
	if e, _ := utils.PathExists(this.confPath); e {
		err = os.Remove(this.confPath); utils.LogError(err)
	}
	
	return 0, err
}

func makeLbAclConfFilePath(lb lbInfo) string {
	return filepath.Join(LB_ROOT_DIR, "conf", fmt.Sprintf("listener-%v-acl.cfg", lb.ListenerUuid))
}

func makeLbPidFilePath(lb lbInfo) string {
	pidPath := filepath.Join(LB_ROOT_DIR, "pid", fmt.Sprintf("lb-%s-listener-%s.pid", lb.LbUuid, lb.ListenerUuid))
	fd, _ := utils.CreateFileIfNotExists(pidPath, os.O_WRONLY | os.O_APPEND, 0666)
	fd.Close()
	return pidPath
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

func makeLbFirewallLocalICMPRuleDescription(lb lbInfo) string {
	return fmt.Sprintf("LBICMP-%v", lb.LbUuid)
}

func makeDropRuleComments(lb lbInfo) string {
	return fmt.Sprintf("%s-%s-%s", utils.LbSynRuleComment, lb.LbUuid, lb.ListenerUuid)
}

func makeLbFirewallRuleComments(lb lbInfo) string {
	return fmt.Sprintf("%s-%s-%s", utils.LbRuleComment, lb.LbUuid, lb.ListenerUuid)
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
		log.Debugf("no need refresh the listener: %v\n", lb.ListenerUuid)
		return
	}
	utils.PanicOnError(err)

	err = listener.preActionListenerServiceStart(); utils.PanicOnError(err)
	//time.Sleep(time.Duration(1) * time.Second)
	if ret, err := listener.startListenerService(); ret != 0 || err != nil {
		log.Errorf("start listener fail %v \n", lb.ListenerUuid)
		listener.rollbackPreActionListenerServiceStart()
		utils.PanicOnError(err)
		return
	}

	if err := listener.postActionListenerServiceStart(); err != nil {
		utils.PanicOnError(err)
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

func removeUnusedCertificate()  {
	files := getCertificateList()
	for _, file := range files {
		if file != "" && !isCertificateUsed(file) {
			err := os.Remove(file); utils.LogError(err)
		}
	}
}

type lbLogLevelConf struct {
	Level string `json:"level"`
}

/**
emerg - 0
alert - 1
err - 3
warn - 4
notice - 5
info - 6 (default)
debug - 7
*/
func doRefreshLogLevel(level string)  {
	lb_log_file, err := ioutil.TempFile(LB_CONF_DIR, "rsyslog")
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

	refreshLbIpTables()
	removeUnusedCertificate()

	return nil
}

func refreshLbIpTables()  {
	/* reinstall all lb firewalls */
	if utils.IsSkipVyosIptables() {
		filterRules := make(map[string][]utils.IptablesRule)
		priNics := utils.GetPrivteInterface()
		for _, listener := range LbListeners {
			var nicname string
			var rules []utils.IptablesRule
			var icmpRules []utils.IptablesRule
			switch v := listener.(type) {
			case *HaproxyListener:
				rules, nicname = v.getIptablesRule()
				icmpRules, _ = v.getIcmpIptablesRule()
				break
			case *GBListener:
				rules, nicname = v.getIptablesRule()
				rules, nicname = v.getIcmpIptablesRule()
				break
			default:
				continue
			}

			filterRules[nicname] = append(filterRules[nicname], rules...)
			filterRules[nicname] = append(filterRules[nicname], icmpRules...)
			for _, priNic := range priNics {
				if priNic != nicname {
					filterRules[priNic] = append(filterRules[priNic], rules...)
				}
			}
		}

		err := utils.SyncFirewallRule(filterRules, utils.LbRuleComment, utils.LOCAL); utils.PanicOnError(err)
	}
}

func delLb(lb lbInfo) {
	listener := getListener(lb)
	if  listener == nil {
		return
	}

	err := listener.stopListenerService(); utils.PanicOnError(err)
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

	refreshLbIpTables()
	removeUnusedCertificate()
	//generateLbHaScript()

	return nil
}

func createCertificateHandler(ctx *server.CommandContext) interface{} {
	certificate := &certificateInfo{}
	ctx.GetCommand(certificate)

	return createCertificate(certificate)
}

func createCertificate(certificate *certificateInfo) interface{} {
    certificatePath := makeCertificatePath(certificate.Uuid)
    if e, _ := utils.PathExists(certificatePath); e {
        /* certificate create api may be called multiple times */
        return nil
    }

    err := utils.MkdirForFile(certificatePath, 0755); utils.PanicOnError(err)
    err = ioutil.WriteFile(certificatePath, []byte(certificate.Certificate), 0755); utils.PanicOnError(err)

    return nil
}

func deleteCertificateHandler(ctx *server.CommandContext) interface{} {
	cmd := &deleteCertificateCmd{}
	ctx.GetCommand(cmd)

	return deleteCertificate(cmd)
}

func deleteCertificate(cmd * deleteCertificateCmd) interface{} {
    certificatePath := makeCertificatePath(cmd.Uuid)
    if e, _ := utils.PathExists(certificatePath); !e {
        return nil
    }

    if err := utils.DeleteFile(certificatePath); err != nil {
        return err
    }

    return nil
}

func init() {
	os.Mkdir(LB_ROOT_DIR, os.ModePerm)
	os.Mkdir(LB_CONF_DIR, os.ModePerm)
	os.Mkdir(LB_PID_DIR, os.ModePerm)
	os.Chmod(LB_PID_DIR, os.ModePerm)
	os.Mkdir(LB_SOCKET_DIR, os.ModePerm | os.ModeSocket)
	LbListeners = make(map[string]interface{}, LISTENER_MAP_SIZE)
	enableLbLog()
	RegisterPrometheusCollector(NewLbPrometheusCollector())

	bash := utils.Bash{
		Command: fmt.Sprintf("/opt/vyatta/sbin/haproxy -ver | grep version"),
	}

	if ret, out, _, err := bash.RunWithReturn(); ret == 0 && err == nil {
		if strings.Contains(out, HAPROXY_VERSION_2_1_0) {
			haproxyVersion = HAPROXY_VERSION_2_1_0
		}
	}
}

type loadBalancerCollector struct {
	statusEntry *prom.Desc
	inByteEntry *prom.Desc
	outByteEntry *prom.Desc
	curSessionNumEntry *prom.Desc
	refusedSessionNumEntry *prom.Desc
	totalSessionNumEntry *prom.Desc
	curSessionUsageEntry *prom.Desc
	concurrentSessionUsageEntry *prom.Desc
}

const (
	LB_UUID = "LbUuid"
	LB_LISTENER_UUID = "ListenerUuid"
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
	return nil
}

func (c *loadBalancerCollector) Update(ch chan<- prom.Metric) error {
	if !IsMaster() {
		return nil
	}

	for listenerUuid, listener := range LbListeners {
		var counters []*LbCounter
		num := 0

		var maxSessionNum, sessionNum uint64
		sessionNum = 0
		lbUuid := ""
		switch listener.(type) {
		case *GBListener:
			gbListener, _ := listener.(*GBListener)
			lbUuid = gbListener.lb.LbUuid
			counters, num = gbListener.getLbCounters(listenerUuid)
			maxSessionNum = (uint64)(gbListener.maxSession)
			/* get total count */
			for _, cnt := range counters {
				sessionNum += cnt.sessionNumber
			}
			break
		case *HaproxyListener:
			haproxyListener, _ := listener.(*HaproxyListener)
			lbUuid = haproxyListener.lb.LbUuid
			counters, num = haproxyListener.getLbCounters(listenerUuid)
			maxSessionNum = (uint64)(haproxyListener.maxSession)
			/* get total count */
			for _, cnt := range counters {
				sessionNum += cnt.sessionNumber
			}

			break
		default:
			log.Infof("can not assert listerner[uuid %s] type", listenerUuid)
			break
		}

		for i := 0; i < num; i++ {
			cnt := counters[i]
			ch <- prom.MustNewConstMetric(c.statusEntry, prom.GaugeValue, float64(cnt.status), cnt.listenerUuid, cnt.ip, lbUuid)
			ch <- prom.MustNewConstMetric(c.inByteEntry, prom.GaugeValue, float64(cnt.bytesIn), cnt.listenerUuid, cnt.ip, lbUuid)
			ch <- prom.MustNewConstMetric(c.outByteEntry, prom.GaugeValue, float64(cnt.bytesOut), cnt.listenerUuid, cnt.ip, lbUuid)
			ch <- prom.MustNewConstMetric(c.curSessionNumEntry, prom.GaugeValue, float64(cnt.sessionNumber), cnt.listenerUuid, cnt.ip, lbUuid)
			ch <- prom.MustNewConstMetric(c.refusedSessionNumEntry, prom.GaugeValue, float64(cnt.refusedSessionNumber), cnt.listenerUuid, cnt.ip, lbUuid)
			ch <- prom.MustNewConstMetric(c.totalSessionNumEntry, prom.GaugeValue, float64(cnt.totalSessionNumber), cnt.listenerUuid, cnt.ip, lbUuid)
			ch <- prom.MustNewConstMetric(c.concurrentSessionUsageEntry, prom.GaugeValue, float64(cnt.concurrentSessionNumber), cnt.listenerUuid, cnt.ip, lbUuid)
		}

		ch <- prom.MustNewConstMetric(c.curSessionUsageEntry, prom.GaugeValue, float64(sessionNum * 100 /maxSessionNum), listenerUuid, lbUuid)
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
	refusedSessionNumber   uint64
	totalSessionNumber   uint64
	concurrentSessionNumber uint64
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

func (this *HaproxyListener) getLbCounters(listenerUuid string) ([]*LbCounter, int) {
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
		counter.refusedSessionNumber = stat.Dreq
		counter.concurrentSessionNumber = stat.Scur + stat.Qcur
		counter.totalSessionNumber = stat.Stot
		counters = append(counters, &counter)
		num++
	}

	return counters, num
}


type GoBetweenServerBackendStat struct {
	Live bool `json:"live"`
	Active_connections uint64 `json:"active_connections"`
	Total_connections uint64 `json:"total_connections"`
	Refused_connections uint64 `json:"refused_connections"`
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

type GoBetweenServerBackend struct {
	Host string `json:"host"`
	Stats GoBetweenServerBackendStat `json:"stats"`
}

type GoBetweenServerStat struct {
	Active_connections uint64 `json:"active_connections"`
	Backends []GoBetweenServerBackend `json:"backends"`
}

/* map to store: <listenerUuid, GBListerner> pair or  or <listenerUuid, HaProxyListener> */
var LbListeners map[string]interface{}
var goBetweenClient = &http.Client{
	Timeout: time.Second * 5,
}

func getListenerCountInLB(lb lbInfo) (counter int) {
	counter = 0;
	for _, listener := range LbListeners {
		var lbtmp lbInfo
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

func (this *GBListener) getLbCounters(listenerUuid string) ([]*LbCounter, int) {
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
		if stat.Stats.Live {
			counter.status = 1
		} else {
			counter.status = 0
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

	return counters, num
}

func enableLbLog() {
	lb_log_file, err := ioutil.TempFile(LB_CONF_DIR, "rsyslog"); utils.PanicOnError(err)
	conf := `$ModLoad imudp
$UDPServerRun 514
local1.info     /var/log/haproxy.log`
	_, err = lb_log_file.Write([]byte(conf)); utils.PanicOnError(err)

	lb_log_rotatoe_file, err := ioutil.TempFile(LB_CONF_DIR, "rotation"); utils.PanicOnError(err)
	rotate_conf := `/var/log/haproxy.log {
size 50M
#daily
rotate 10
compress
copytruncate
notifempty
missingok
}
/var/log/gobetween*.log {
size 50M
#daily
rotate 10
compress
copytruncate
notifempty
missingok
}`
	_, err = lb_log_rotatoe_file.Write([]byte(rotate_conf)); utils.PanicOnError(err)

	/* add log rotate for /var/log/auth.log */
	auth_rotatoe_file, err := ioutil.TempFile(LB_CONF_DIR, "auth"); utils.PanicOnError(err)
	auth_rotate_conf := `/var/log/auth.log {
size 102400k
daily
rotate 10
compress
copytruncate
notifempty
missingok
}`
	_, err = auth_rotatoe_file.Write([]byte(auth_rotate_conf)); utils.PanicOnError(err)
	utils.SudoMoveFile(lb_log_file.Name(), "/etc/rsyslog.d/haproxy.conf")
	utils.SudoMoveFile(lb_log_rotatoe_file.Name(), "/etc/logrotate.d/haproxy")
	utils.SudoMoveFile(auth_rotatoe_file.Name(), "/etc/logrotate.d/auth")
}

func init()  {
	gobetweenListeners = map[string]*GBListener{}
}

func LbEntryPoint() {
	server.RegisterAsyncCommandHandler(REFRESH_LB_PATH, server.VyosLock(refreshLb))
	server.RegisterAsyncCommandHandler(REFRESH_LB_LOG_LEVEL_PATH, server.VyosLock(refreshLogLevel))
	server.RegisterAsyncCommandHandler(DELETE_LB_PATH, server.VyosLock(deleteLb))
	server.RegisterAsyncCommandHandler(CREATE_CERTIFICATE_PATH, server.VyosLock(createCertificateHandler))
	server.RegisterAsyncCommandHandler(DELETE_CERTIFICATE_PATH, server.VyosLock(deleteCertificateHandler))
}