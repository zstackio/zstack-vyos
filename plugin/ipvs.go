package plugin

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"zstack-vyos/server"
	"zstack-vyos/utils"

	prom "github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

type IpvsConnectionType int

const (
	IpvsConnectionTypeDR IpvsConnectionType = iota + 1
	IpvsConnectionTypeNAT
	IpvsConnectionTypeTUNNEL
)

const (
	IPVS_LOG_CHAIN_NAME      = "ipvs-log"
	IPVS_FULL_NAT_CHAIN_NAME = "ipvs-full-nat"
	IPVS_LOG_IPSET_NAME      = "ipvs-set"
	IPVS_LOG_IPSET6_NAME     = "ipvs6-set"
	IPVS_LOG_PREFIX          = "ipvs-log"

	IPVS_HEALTH_CHECK_BIN_FILE      = "/usr/local/bin/ipvsHealthCheck"
	IPVS_HEALTH_CHECK_BIN_FILE_VYOS = "/opt/vyatta/sbin/ipvsHealthCheck"
	IPVS_HEALTH_CHECK_CONFIG_FILE   = "/etc/ipvs/healthcheck.conf"
	IPVS_HEALTH_CHECK_LOG_FILE      = "/var/log/ipvs_health_check.log"
	IPVS_HEALTH_CHECK_START_LOG     = "/var/log/ipvs_health_check_start.log"
	IPVS_HEALTH_CHECK_PID_FILE      = "/var/run/ipvs_health_check.pid"
)

func (cType IpvsConnectionType) String() string {
	switch cType {
	case IpvsConnectionTypeDR:
		return "-g"
	case IpvsConnectionTypeNAT:
		return "-m"
	case IpvsConnectionTypeTUNNEL:
		return "-i"
	default:
		return "Unknown"
	}
}

/*
	ZStack need 4 scheduling methods:

scheduling-method Algorithm for allocating TCP connections and UDP datagrams to real servers. Scheduling algorithms are implemented as kernel modules. Ten are shipped with the Linux Virtual Server:
rr - Robin Robin: distributes jobs equally amongst the available real servers.
wrr - Weighted Round Robin: assigns jobs to real servers proportionally to there real servers' weight. Servers with higher weights receive new jobs first and get more jobs than servers with lower weights. Servers with equal weights get an equal distribution of new jobs.
lc - Least-Connection: assigns more jobs to real servers with fewer active jobs.
wlc - Weighted Least-Connection: assigns more jobs to servers with fewer jobs and relative to the real servers' weight (Ci/Wi). This is the default.
lblc - Locality-Based Least-Connection: assigns jobs destined for the same IP address to the same server if the server is not overloaded and available; otherwise assign jobs to servers with fewer jobs, and keep it for future assignment.
lblcr - Locality-Based Least-Connection with Replication: assigns jobs destined for the same IP address to the least-connection node in the server set for the IP address. If all the node in the server set are over loaded, it picks up a node with fewer jobs in the cluster and adds it in the sever set for the target. If the server set has not been modified for the specified time, the most loaded node is removed from the server set, in order to avoid high degree of replication.
dh - Destination Hashing: assigns jobs to servers through looking up a statically assigned hash table by their destination IP addresses.
sh - Source Hashing: assigns jobs to servers through looking up a statically assigned hash table by their source IP addresses.
sed - Shortest Expected Delay: assigns an incoming job to the server with the shortest expected delay. The expected delay that the job will experience is (Ci + 1) / Ui if sent to the ith server, in which Ci is the number of jobs on the the ith server and Ui is the fixed service rate (weight) of the ith server.
nq - Never Queue: assigns an incoming job to an idle server if there is, instead of waiting for a fast one; if all the servers are busy, it adopts the Shortest Expected Delay policy to assign the job.
*/
type IpvsSchedulerType int

const (
	IpvsSchedulerRR IpvsSchedulerType = iota + 1
	IpvsSchedulerWRR
	IpvsSchedulerLC
	IpvsSchedulerSH
)

func (sch IpvsSchedulerType) String() string {
	switch sch {
	case IpvsSchedulerRR:
		return "rr"
	case IpvsSchedulerWRR:
		return "wrr"
	case IpvsSchedulerLC:
		return "lc"
	case IpvsSchedulerSH:
		return "sh"
	default:
		return "Unknown"
	}
}

func GetIpvsSchedulerTypeFromString(sch string) IpvsSchedulerType {
	switch strings.ToLower(sch) {
	case "roundrobin":
		return IpvsSchedulerRR
	case IpvsSchedulerRR.String():
		return IpvsSchedulerRR
	case "weightroundrobin":
		return IpvsSchedulerWRR
	case IpvsSchedulerWRR.String():
		return IpvsSchedulerWRR
	case "leastconn":
		return IpvsSchedulerLC
	case IpvsSchedulerLC.String():
		return IpvsSchedulerLC
	case "source":
		return IpvsSchedulerSH
	case IpvsSchedulerSH.String():
		return IpvsSchedulerSH
	default:
		return IpvsSchedulerRR
	}
}

type IpvsBackendServer struct {
	/* for ipvsadm, ConnectionType is configure for each backend server */
	ConnectionType string // "dr", "tunnel", "nat"
	Weight         string // "default 1"
	BackendIp      string
	BackendPort    string
	Counter        LbCounter

	*IpvsFrontendService
}

type IpvsFrontendService struct {
	/* for keepalived, ConnectionType is configure for frontEndService */
	ConnectionType string // "dr", "tunnel", "nat"
	ProtocolType   string // "tcp", "udp", "fwmark"
	Scheduler      string // "rr|wrr|lc|wlc|lblc|lblcr|dh|sh|sed|nq"
	FrontIp        string
	FrontPort      string
	SessionNumber  uint64

	BackendServers map[string]*IpvsBackendServer
	LbInfo
	LbParams
}

type IpvsConf struct {
	Services map[string]*IpvsFrontendService
}

var gIpvsConf *IpvsConf
var ipvsHealthCheckPidMon *utils.PidMon

/* first key: lbUuid, second key is listenerUuid */
var gIpvsLbInfoMap map[string]map[string]LbInfo
var gEnableLog = false

type IpvsHealthCheckBackendServer struct {
	LbUuid       string
	ListenerUuid string

	ConnectionType string // "dr", "tunnel", "nat"
	ProtocolType   string // "tcp", "udp", "fwmark"
	Scheduler      string // "rr|wrr|lc|wlc|lblc|lblcr|dh|sh|sed|nq"
	FrontIp        string
	FrontPort      string

	Weight      string // "default 1"
	BackendIp   string
	BackendPort string

	HealthCheckProtocol string
	HealthCheckPort     int
	HealthCheckInterval int
	HealthCheckTimeout  int
	HealthyThreshold    uint
	UnhealthyThreshold  uint

	MaxConnection int
	MinConnection int
}

func (bs *IpvsHealthCheckBackendServer) CopyParamsFrom(other *IpvsHealthCheckBackendServer) {
	bs.ConnectionType = other.ConnectionType
	bs.Scheduler = other.Scheduler
	bs.Weight = other.Weight
	bs.HealthCheckProtocol = other.HealthCheckProtocol
	bs.HealthCheckPort = other.HealthCheckPort
	bs.HealthCheckInterval = other.HealthCheckInterval
	bs.HealthCheckTimeout = other.HealthCheckTimeout
	bs.HealthyThreshold = other.HealthyThreshold
	bs.UnhealthyThreshold = other.UnhealthyThreshold
	bs.MaxConnection = other.MaxConnection
	bs.MinConnection = other.MinConnection
}

type IpvsHealthCheckFrontService struct {
	LbUuid       string
	ListenerUuid string

	ConnectionType string // "dr", "tunnel", "nat"
	ProtocolType   string // "tcp", "udp", "fwmark"
	Scheduler      string // "rr|wrr|lc|wlc|lblc|lblcr|dh|sh|sed|nq"
	FrontIp        string
	FrontPort      string

	BackendServers []*IpvsHealthCheckBackendServer
}

type IpvsHealthCheckConf struct {
	Services []*IpvsHealthCheckFrontService
}

func (hcConf *IpvsHealthCheckConf) FromIpvsConf(conf *IpvsConf) *IpvsHealthCheckConf {
	for _, fs := range conf.Services {
		hcFs := IpvsHealthCheckFrontService{
			LbUuid:       fs.LbInfo.LbUuid,
			ListenerUuid: fs.LbInfo.ListenerUuid,

			FrontIp:        fs.FrontIp,
			FrontPort:      fs.FrontPort,
			ProtocolType:   fs.ProtocolType,
			Scheduler:      fs.Scheduler,
			ConnectionType: fs.ConnectionType,

			BackendServers: []*IpvsHealthCheckBackendServer{},
		}

		for _, bs := range fs.BackendServers {
			hcBs := IpvsHealthCheckBackendServer{
				LbUuid:       bs.LbUuid,
				ListenerUuid: bs.ListenerUuid,

				ConnectionType: bs.ConnectionType,
				ProtocolType:   bs.ProtocolType,
				Scheduler:      bs.Scheduler,
				FrontIp:        bs.FrontIp,
				FrontPort:      bs.FrontPort,

				Weight:        bs.Weight,
				BackendIp:     bs.BackendIp,
				BackendPort:   bs.BackendPort,
				MaxConnection: bs.maxConnection,
				MinConnection: bs.minConnection,

				HealthCheckProtocol: bs.healthCheckProtocl,
				HealthCheckPort:     bs.healthCheckPort,
				HealthCheckInterval: bs.healthCheckInterval,
				HealthCheckTimeout:  bs.healthCheckTimeout,
				HealthyThreshold:    bs.healthyThreshold,
				UnhealthyThreshold:  bs.unhealthyThreshold,
			}

			hcFs.BackendServers = append(hcFs.BackendServers, &hcBs)
		}

		hcConf.Services = append(hcConf.Services, &hcFs)
	}

	return hcConf
}

func (ipvs *IpvsConf) ipvsadmSave() (*IpvsConf, error) {
	b := utils.Bash{
		Command: "ipvsadm-save -n",
		Sudo:    true,
	}

	ret, o, _, err := b.RunWithReturn()
	if ret != 0 || err != nil {
		return nil, fmt.Errorf("failed to execute ipvsadm-save, %v", err)
	}

	err = ipvs.ParseIpvs(o)
	return ipvs, err
}

func (ipvs *IpvsConf) ParseIpvs(content string) error {
	services := map[string]*IpvsFrontendService{}

	/* # ipvsadm-save -n
	-A -t 172.25.116.175:80 -s rr
	-a -t 172.25.116.175:80 -r 192.168.1.180:80 -m -w 1
	-a -t 172.25.116.175:80 -r 192.168.1.230:80 -m -w 1
	-A -u 172.25.116.175:8080 -s rr
	-a -u 172.25.116.175:8080 -r 192.168.1.180:80 -m -w 1
	-a -u 172.25.116.175:8080 -r 192.168.1.230:80 -m -w 1
	*/
	lines := strings.Split(content, "\n")
	var service *IpvsFrontendService
	for _, line := range lines {
		line := strings.TrimSpace(line)
		if line == "" {
			continue
		}

		items := strings.Fields(line)
		protocol := items[1]

		if items[0] == "-A" {
			ip := ""
			port := ""
			if strings.Contains(items[2], "]") {
				ipports := strings.Split(items[2], "]")
				ip = strings.Trim(ipports[0], "[")
				port = strings.Trim(ipports[1], ":")
			} else {
				ipports := strings.Split(items[2], ":")
				ip = ipports[0]
				port = ipports[1]
			}

			scheduler := items[4]
			info := LbInfo{}
			if strings.Contains(ip, ":") {
				info.Vip6 = ip
			} else {
				info.Vip = ip
			}
			info.LoadBalancerPort, _ = strconv.Atoi(port)
			if protocol == "-u" {
				info.Mode = "udp"
			}

			param := LbParams{}
			param.balancerAlgorithm = scheduler

			service = NewIpvsFrontService(info, param, ip, map[string]*IpvsBackendServer{})
			services[service.getFrontendServiceKey()] = service
		} else if items[0] == "-a" {
			backendIp := ""
			backendPort := ""
			if strings.Contains(items[4], "]") {
				ipports := strings.Split(items[4], "]")
				backendIp = strings.Trim(ipports[0], "[")
				backendPort = strings.Trim(ipports[1], ":")
			} else {
				ipports := strings.Split(items[4], ":")
				backendIp = ipports[0]
				backendPort = ipports[1]
			}

			service.ConnectionType = items[5]
			weight := items[7]
			backend := NewIpvsBackendServer(backendIp, backendPort, weight, service)
			service.BackendServers[backend.GetBackendKey()] = backend
		}
	}

	ipvs.Services = services
	return nil
}

func (conf *IpvsConf) ReloadIpvsHealthCheckConfig() {
	hcConf := IpvsHealthCheckConf{}
	hcConf.FromIpvsConf(conf)
	err := utils.JsonStoreConfig(IPVS_HEALTH_CHECK_CONFIG_FILE, hcConf)
	utils.PanicOnError(err)

	pid, err := utils.ReadPid(IPVS_HEALTH_CHECK_PID_FILE)
	utils.PanicOnError(err)

	b := utils.Bash{
		Command: fmt.Sprintf("kill -HUP %d", pid),
		Sudo:    true,
	}

	err = b.Run()
	utils.PanicOnError(err)
}

func NewIpvsBackendServer(serverIp, serverPort, weight string, frontService *IpvsFrontendService) *IpvsBackendServer {
	return &IpvsBackendServer{
		ConnectionType:      frontService.ConnectionType,
		Weight:              weight,
		BackendIp:           serverIp,
		BackendPort:         serverPort,
		Counter:             LbCounter{lbUuid: frontService.LbUuid, listenerUuid: frontService.ListenerUuid},
		IpvsFrontendService: frontService,
	}
}

func NewIpvsFrontService(info LbInfo, param LbParams, frontIp string, servers map[string]*IpvsBackendServer) *IpvsFrontendService {
	connectionType := IpvsConnectionTypeNAT.String()
	protocolType := "-u"
	if info.Mode == LB_MODE_HTTPS || info.Mode == LB_MODE_HTTP || info.Mode == LB_MODE_TCP {
		protocolType = "-t"
	}
	scheduler := GetIpvsSchedulerTypeFromString(param.balancerAlgorithm)
	return &IpvsFrontendService{
		ConnectionType: connectionType,
		ProtocolType:   protocolType,
		Scheduler:      scheduler.String(),
		FrontIp:        frontIp,
		FrontPort:      fmt.Sprintf("%d", info.LoadBalancerPort),
		SessionNumber:  0,
		BackendServers: servers,
		LbInfo:         info,
		LbParams:       param,
	}
}

func NewIpvsConfFromSave() (*IpvsConf, error) {
	conf := IpvsConf{
		Services: map[string]*IpvsFrontendService{},
	}
	_, err := conf.ipvsadmSave()
	return &conf, err
}

func (fs *IpvsFrontendService) getFrontendServiceKey() string {
	return fs.ProtocolType + "-" + fs.FrontIp + "-" + fs.FrontPort
}

func (fs *IpvsFrontendService) EnableIpvsLog() (err error) {

	ipset := utils.GetIpSet(IPVS_LOG_IPSET_NAME)
	ipset.Member = []string{}
	protol := "udp"
	if fs.ProtocolType == "-t" {
		protol = "tcp"
	}

	frontIp := fs.FrontIp
	ip := net.ParseIP(frontIp)
	if ip != nil && ip.To4() == nil {
		frontIp = fmt.Sprintf("[%s]", frontIp)
		/* TODO: ip6tables is not added */
		return nil
	}

	err = ipset.AddMember([]string{frontIp + "," + protol + ":" + fs.FrontPort})
	utils.PanicOnError(err)

	return nil
}

func (fs *IpvsFrontendService) DisableIpvsLog() (err error) {
	ipset := utils.GetIpSet(IPVS_LOG_IPSET_NAME)
	ipset.Member = []string{}
	protol := "udp"
	if fs.ProtocolType == "-t" {
		protol = "tcp"
	}

	frontIp := fs.FrontIp
	ip := net.ParseIP(frontIp)
	if ip != nil && ip.To4() == nil {
		frontIp = fmt.Sprintf("[%s]", frontIp)
	}

	ipset.DeleteMember([]string{frontIp + "," + protol + ":" + fs.FrontPort})

	return nil
}

func refreshIpvsFirewallRuleByVyos(services map[string]*IpvsFrontendService) error {
	tree := server.NewParserFromShowConfiguration().Tree

	//remove old rule, the reconfigure it
	nics, _ := utils.GetAllNics()
	for _, nic := range nics {
		for {
			if r := tree.FindFirewallRuleByDescriptionRegex(
				nic.Name, "in", utils.IpvsComment, utils.StringRegCompareFn); r != nil {
				r.Delete()
			} else {
				break
			}
		}
		for {
			if r := tree.FindFirewallRuleByDescriptionRegex(
				nic.Name, "local", utils.IpvsComment, utils.StringRegCompareFn); r != nil {
				r.Delete()
			} else {
				break
			}
		}
	}

	changed := false
	for _, fs := range services {
		changed = true
		des := makeLbFirewallRuleDescription(fs.LbInfo)
		nicname, err := utils.GetNicNameByMac(fs.PublicNic)
		utils.PanicOnError(err)
		proto := utils.IPTABLES_PROTO_UDP
		if fs.ProtocolType == "-t" || fs.ProtocolType == "tcp" {
			proto = utils.IPTABLES_PROTO_TCP
		}

		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("destination address %v", fs.Vip),
				fmt.Sprintf("destination port %v", fs.LoadBalancerPort),
				fmt.Sprintf("protocol %s", proto),
				"action accept",
			)

			configureInternalFirewallRule(tree, des,
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("destination address %v", fs.Vip),
				fmt.Sprintf("destination port %v", fs.LoadBalancerPort),
				fmt.Sprintf("protocol %s", proto),
				"action accept",
			)
		}

		tree.AttachFirewallToInterface(nicname, "local")

		for _, bs := range fs.BackendServers {
			priNic := utils.GetNicForRoute(bs.BackendIp)
			priNic = strings.TrimSpace(priNic)
			if r := tree.FindFirewallRuleByDescription(priNic, "in", des); r == nil {
				tree.SetFirewallOnInterface(nicname, "in",
					fmt.Sprintf("description %v", des),
					fmt.Sprintf("source address %v", bs.BackendIp),
					fmt.Sprintf("source port %v", bs.BackendPort),
					fmt.Sprintf("protocol %s", proto),
					"action accept",
				)
			}
		}
	}

	if changed {
		tree.Apply(false)
	}

	return nil
}

func refreshIpvsFullNatRules(services map[string]*IpvsFrontendService) {
	if !utils.IsSLB() {
		// only slb need full nat rule
		return
	}

	table := utils.NewIpTables(utils.NatTable)
	var rules []*utils.IpTableRule

	table.RemoveIpTableRuleByComments(utils.IpvsComment)

	for _, fs := range services {
		log.Debugf("refreshIpvsFullNatRules service %+v", fs)
		proto := utils.IPTABLES_PROTO_UDP
		if fs.ProtocolType == "-t" || fs.ProtocolType == "tcp" {
			proto = utils.IPTABLES_PROTO_TCP
		}

		for _, bs := range fs.BackendServers {
			if strings.Contains(bs.BackendIp, ":") {
				/* TODO: add ipv6 rules */
				continue
			}

			nicname := utils.GetNicForRoute(bs.BackendIp)
			nicname = strings.TrimSpace(nicname)
			nicIp, err := utils.GetIpByNicName(nicname)
			utils.PanicOnError(err)
			rule := utils.NewIpTableRule(IPVS_FULL_NAT_CHAIN_NAME)
			rule.SetDstIp(bs.BackendIp + "/32").SetDstPort(bs.BackendPort).SetProto(proto)
			rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetSnatTargetIp(nicIp)
			rule.SetComment(utils.IpvsComment)
			rules = append(rules, rule)
		}
	}

	if gEnableLog {
		rule := utils.NewIpTableRule(IPVS_LOG_CHAIN_NAME)
		rule.SetActionLog(IPVS_LOG_PREFIX)
		rules = append(rules, rule)
	}

	if len(rules) != 0 {
		table.AddIpTableRules(rules)
	}

	err := table.Apply()
	utils.PanicOnError(err)
}

func refreshIpvsFirewallRuleByIptables(services map[string]*IpvsFrontendService) error {
	table := utils.NewIpTables(utils.FirewallTable)
	var rules []*utils.IpTableRule

	table.RemoveIpTableRuleByComments(utils.IpvsComment)

	for _, fs := range services {
		nicname, err := utils.GetNicNameByMac(fs.LbInfo.PublicNic)
		utils.PanicOnError(err)

		proto := utils.IPTABLES_PROTO_UDP
		if fs.ProtocolType == "-t" || fs.ProtocolType == "tcp" {
			proto = utils.IPTABLES_PROTO_TCP
		}

		if !strings.Contains(fs.FrontIp, ":") {
			rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
			rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(utils.IpvsComment)
			rule.SetDstIp(fs.FrontIp).SetDstPort(fmt.Sprintf("%d", fs.LbInfo.LoadBalancerPort)).SetProto(proto)
			rules = append(rules, rule)

			priNics := utils.GetPrivteInterface()
			for _, priNic := range priNics {
				newRule := rule.Copy()
				newRule.SetChainName(utils.GetRuleSetName(priNic, utils.RULESET_LOCAL))
				rules = append(rules, rule)
			}
		}

		for _, bs := range fs.BackendServers {
			if strings.Contains(bs.BackendIp, ":") {
				continue
			}

			nicname := utils.GetNicForRoute(bs.BackendIp)
			nicname = strings.TrimSpace(nicname)
			rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_IN))
			rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(utils.IpvsComment)
			rule.SetSrcIp(bs.BackendIp).SetSrcPort(bs.BackendPort).SetProto(proto)
			rules = append(rules, rule)
		}
	}

	if len(rules) == 0 {
		return nil
	}

	table.AddIpTableRules(rules)
	return table.Apply()
}

func RefreshIpvsBackend() error {
	services := map[string]*IpvsFrontendService{}
	for _, lb := range gIpvsLbInfoMap {
		for _, listener := range lb {
			if strings.ToLower(listener.Mode) != "udp" {
				/* current only udp lb use ipvs */
				continue
			}

			lbParam := ParseLbParams(listener)

			var fs4, fs6 *IpvsFrontendService
			if listener.Vip != "" {
				fs4 = NewIpvsFrontService(listener, lbParam, listener.Vip, map[string]*IpvsBackendServer{})
				services[fs4.getFrontendServiceKey()] = fs4
			}
			if listener.Vip6 != "" {
				fs6 = NewIpvsFrontService(listener, lbParam, listener.Vip6, map[string]*IpvsBackendServer{})
				services[fs6.getFrontendServiceKey()] = fs6
			}

			for _, sg := range listener.ServerGroups {
				for _, bs := range sg.BackendServers {
					if listener.Vip != "" {
						bs := NewIpvsBackendServer(bs.Ip, fmt.Sprintf("%d", listener.InstancePort), fmt.Sprintf("%d", bs.Weight), fs4)
						if lbParam.healthCheckPort == 0 {
							bs.healthCheckPort = listener.InstancePort
						}
						fs4.BackendServers[bs.GetBackendKey()] = bs
					}

					if listener.Vip6 != "" {
						bs := NewIpvsBackendServer(bs.Ip, fmt.Sprintf("%d", listener.InstancePort), fmt.Sprintf("%d", bs.Weight), fs6)
						if lbParam.healthCheckPort == 0 {
							bs.healthCheckPort = listener.InstancePort
						}
						fs6.BackendServers[bs.GetBackendKey()] = bs
					}
				}
			}
		}
	}

	gIpvsConf = &IpvsConf{Services: services}
	gIpvsConf.ReloadIpvsHealthCheckConfig()

	if utils.IsSkipVyosIptables() {
		err := refreshIpvsFirewallRuleByIptables(services)
		utils.PanicOnError(err)
	} else {
		err := refreshIpvsFirewallRuleByVyos(services)
		utils.PanicOnError(err)
	}

	refreshIpvsFullNatRules(services)

	return nil
}

func RefreshIpvsService(lbs map[string]LbInfo, enableLog bool) error {
	tempLbMaps := map[string]map[string]LbInfo{}
	for _, info := range lbs {
		if _, ok := tempLbMaps[info.LbUuid]; !ok {
			tempLbMaps[info.LbUuid] = make(map[string]LbInfo)
			tempLbMaps[info.LbUuid][info.ListenerUuid] = info
		} else {
			tempLbMaps[info.LbUuid][info.ListenerUuid] = info
		}
	}

	for lbUuid, lb := range tempLbMaps {
		for listenerUuid, listener := range lb {
			/* if there is no backend, delete listener */
			if len(listener.NicIps) == 0 {
				log.Debugf("no nics: %s", listenerUuid)
				delete(lb, listenerUuid)
				continue
			}

			if len(listener.ServerGroups) == 0 {
				log.Debugf("no server group: %s", listenerUuid)
				delete(lb, listenerUuid)
				continue
			}

			var servers []string
			for _, serverGroup := range listener.ServerGroups {
				for _, bs := range serverGroup.BackendServers {
					servers = append(servers, bs.Ip)
				}
			}
			if len(servers) == 0 {
				log.Debugf("no server group backend: %s", listenerUuid)
				delete(lb, listenerUuid)
				continue
			}
		}

		if len(lb) == 0 {
			log.Debugf("delete lb: %s", lbUuid)
			delete(gIpvsLbInfoMap, lbUuid)
		} else {
			gIpvsLbInfoMap[lbUuid] = lb
		}
	}

	gEnableLog = enableLog
	err := RefreshIpvsBackend()
	utils.PanicOnError(err)

	return nil
}

func DelIpvsService(lbs map[string]LbInfo) {
	for _, info := range lbs {
		delete(gIpvsLbInfoMap, info.LbUuid)
	}

	err := RefreshIpvsBackend()
	utils.PanicOnError(err)
}

func (bs *IpvsBackendServer) GetBackendKey() string {
	proto := "udp"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "tcp"
	}

	return proto + "-" + bs.FrontIp + "-" + bs.FrontPort + "-" + bs.BackendIp + "-" + bs.BackendPort
}

func getIpvsBackend(proto, frontIp, frontPort, backendIp, backendPort string) *IpvsBackendServer {
	for _, fs := range gIpvsConf.Services {
		for _, bs := range fs.BackendServers {
			if bs.BackendIp == backendIp && bs.BackendPort == backendPort &&
				bs.FrontIp == frontIp && bs.FrontPort == frontPort &&
				bs.ProtocolType == proto {
				return bs
			}
		}
	}

	log.Debugf("backend not found for :%s-%s-%s-%s-%s-%s", proto, frontIp, frontPort, backendIp, backendPort)
	return nil
}

func GetIpvsFrontService(listenerUuid string) *IpvsFrontendService {
	for _, fs := range gIpvsConf.Services {
		if fs.ListenerUuid == listenerUuid {
			return fs
		}
	}

	log.Debugf("frontend not found for listenerUuid :%s", listenerUuid)
	return nil
}

func UpdateIpvsMetrics(c *loadBalancerCollector, ch chan<- prom.Metric) (err error) {
	if gIpvsConf.Services == nil {
		return
	}

	UpdateIpvsCounters()

	/* update listener total session */
	for _, fs := range gIpvsConf.Services {
		fs.SessionNumber = 0
		for _, bs := range fs.BackendServers {
			if bs.Counter.Status != 0 {
				fs.SessionNumber += bs.Counter.sessionNumber
			}
		}
	}

	for _, fs := range gIpvsConf.Services {
		maxConnection := 0
		for _, bs := range fs.BackendServers {
			cnt := &bs.Counter
			maxConnection = bs.maxConnection
			ch <- prom.MustNewConstMetric(c.statusEntry, prom.GaugeValue, float64(cnt.Status), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.inByteEntry, prom.GaugeValue, float64(cnt.bytesIn), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.outByteEntry, prom.GaugeValue, float64(cnt.bytesOut), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.curSessionNumEntry, prom.GaugeValue, float64(cnt.sessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.refusedSessionNumEntry, prom.GaugeValue, float64(cnt.refusedSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.totalSessionNumEntry, prom.GaugeValue, float64(cnt.totalSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.concurrentSessionUsageEntry, prom.GaugeValue, float64(cnt.concurrentSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
		}
		if maxConnection > 0 {
			ch <- prom.MustNewConstMetric(c.curSessionUsageEntry, prom.GaugeValue, float64(fs.SessionNumber*100/(uint64)(maxConnection)), fs.ListenerUuid, fs.LbUuid)
		}
	}

	return nil
}

func UpdateIpvsCounters() {
	for _, fs := range gIpvsConf.Services {
		for _, bs := range fs.BackendServers {
			/* if it can not be updated by ipvsadm -L -n --stats, it's down*/
			bs.Counter.ip = bs.BackendIp
			bs.Counter.Status = 0
		}
	}

	b := utils.Bash{
		/*
			# ipvsadm -L -n --stats
			IP Virtual Server version 1.2.1 (size=4096)
			Prot LocalAddress:Port               Conns   InPkts  OutPkts  InBytes OutBytes
			  -> RemoteAddress:Port
			TCP  172.25.116.175:80                   0        0        0        0        0
			  -> 192.168.1.180:80                    0        0        0        0        0
			  -> 192.168.1.230:80                    0        0        0        0        0
			UDP  172.25.116.175:8080                 0        0        0        0        0
			  -> 192.168.1.180:80                    0        0        0        0        0
			  -> 192.168.1.230:80                    0        0        0        0        0
		*/
		Command: "ipvsadm -L -n --stats",
		Sudo:    true,
		NoLog:   true,
	}

	ret, o, _, err := b.RunWithReturn()
	if ret != 0 || err != nil {
		return
	}

	frontIp := ""
	frontPort := ""
	proto := "-u"
	backendIp := ""
	backendPort := ""
	lines := strings.Split(o, "\n")
	lines = lines[3:] //ignore the first 3 lines
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || len(line) == 0 {
			continue
		}
		items := strings.Fields(line)
		if items[0] == "TCP" || items[0] == "UDP" {
			ipports := strings.Split(items[1], ":")
			frontIp = strings.Join(ipports[0:len(ipports)-1], ":")
			frontIp = strings.Trim(frontIp, "[")
			frontIp = strings.Trim(frontIp, "]")
			frontPort = ipports[len(ipports)-1]
		} else if items[0] == "->" {
			ipports := strings.Split(items[1], ":")
			backendIp = strings.Join(ipports[0:len(ipports)-1], ":")
			backendIp = strings.Trim(backendIp, "[")
			backendIp = strings.Trim(backendIp, "]")
			backendPort = ipports[len(ipports)-1]

			bs := getIpvsBackend(proto, frontIp, frontPort, backendIp, backendPort)
			if bs == nil {
				log.Debugf("GetIpvsCounters backend server for key:%s:%s:%s:%s:%s not found",
					proto, frontIp, frontPort, backendIp, backendPort)
				break
			}

			bs.Counter.ip = backendIp
			bs.Counter.Status = 1
			bs.Counter.bytesIn, _ = strconv.ParseUint(strings.Trim(items[5], " "), 10, 64)
			bs.Counter.bytesOut, _ = strconv.ParseUint(strings.Trim(items[6], " "), 10, 64)
		} else {
			frontIp = ""
			frontPort = ""
		}
	}

	b = utils.Bash{
		/* example
		# ipvsadm -Ln --thresholds
		IP Virtual Server version 1.2.1 (size=4096)
		Prot LocalAddress:Port            Uthreshold Lthreshold ActiveConn InActConn
		  -> RemoteAddress:Port
		TCP  172.25.116.175:80 rr
		  -> 192.168.1.180:80             0          0          0          0
		  -> 192.168.1.181:80             10000      0          0          0
		  -> 192.168.1.182:80             10000      100        0          0
		*/
		Command: "ipvsadm -Ln --thresholds",
		Sudo:    true,
		NoLog:   true,
	}

	ret, o, _, err = b.RunWithReturn()
	if ret != 0 || err != nil {
		return
	}
	lines = strings.Split(o, "\n")
	lines = lines[3:] //ignore the first 3 lines
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || len(line) == 0 {
			continue
		}
		items := strings.Fields(line)
		if items[0] == "TCP" || items[0] == "UDP" {
			ipports := strings.Split(items[1], ":")
			frontIp = strings.Join(ipports[0:len(ipports)-1], ":")
			frontIp = strings.Trim(frontIp, "[")
			frontIp = strings.Trim(frontIp, "]")
			frontPort = ipports[len(ipports)-1]
		} else if items[0] == "->" {
			ipports := strings.Split(items[1], ":")
			backendIp = strings.Join(ipports[0:len(ipports)-1], ":")
			backendIp = strings.Trim(backendIp, "[")
			backendIp = strings.Trim(backendIp, "]")
			backendPort = ipports[len(ipports)-1]

			bs := getIpvsBackend(proto, frontIp, frontPort, backendIp, backendPort)
			if bs == nil {
				log.Debugf("GetIpvsCounters backend server for key:%s:%s:%s:%s:%s not found",
					proto, frontIp, frontPort, backendIp, backendPort)
				break
			}

			bs.Counter.sessionNumber, _ = strconv.ParseUint(strings.Trim(items[4], " "), 10, 64)
			bs.Counter.concurrentSessionNumber = bs.Counter.sessionNumber
			bs.Counter.refusedSessionNumber, _ = strconv.ParseUint(strings.Trim(items[5], " "), 10, 64)
			bs.Counter.totalSessionNumber = bs.Counter.sessionNumber + bs.Counter.refusedSessionNumber
		} else {
			frontIp = ""
			frontPort = ""
		}
	}
}

func StopIpvsHealthCheck() {
	if !utils.IsEuler2203() {
		ipvsHealthCheckPidMon.Destroy()
	} else {
		utils.ServiceOperation("ipvsHealthCheck", "stop")
	}
}

func startIpvsHealthCheckPidMon() {
	/* start ipvsHealthCheck */
	binPath := IPVS_HEALTH_CHECK_BIN_FILE
	if utils.IsVYOS() {
		binPath = IPVS_HEALTH_CHECK_BIN_FILE_VYOS
	}
	pid, err := utils.FindFirstPIDByPSExtern(true, binPath)
	if err != nil {
		log.Debugf("start ipvs health check")
		b := utils.Bash{
			Command: fmt.Sprintf("nohup %s -f %s -log %s -p %s > %s 2>&1 &", binPath,
				IPVS_HEALTH_CHECK_CONFIG_FILE, IPVS_HEALTH_CHECK_LOG_FILE,
				IPVS_HEALTH_CHECK_PID_FILE, IPVS_HEALTH_CHECK_START_LOG),
			Sudo: true,
		}
		err := b.Run()
		utils.PanicOnError(err)
	}

	time.Sleep(1 * time.Second)

	pid, err = utils.FindFirstPIDByPSExtern(true, binPath)
	log.Debugf("ipvs health check pid %d", pid)

	ipvsHealthCheckPidMon = utils.NewPidMon(pid, func() int {
		log.Warnf("start ipvs health check in PidMon")
		b := utils.Bash{
			Command: fmt.Sprintf("nohup %s -f %s -log %s -p %s > %s 2>&1 &", binPath,
				IPVS_HEALTH_CHECK_CONFIG_FILE, IPVS_HEALTH_CHECK_LOG_FILE,
				IPVS_HEALTH_CHECK_PID_FILE, IPVS_HEALTH_CHECK_START_LOG),
			Sudo: true,
		}
		err := b.Run()
		if err != nil {
			log.Warnf("failed to start ipvs health check: %v", err)
			return -1
		}

		pid, err := utils.FindFirstPIDByPSExtern(true, binPath)
		if err != nil {
			log.Warnf("failed to read ipvs health check pid: %v", err)
			return -1
		}

		return pid
	})
	log.Debugf("created ipvs health check PidMon")
	err = ipvsHealthCheckPidMon.Start()
	utils.PanicOnError(err)
}

func InitIpvs() {
	gIpvsConf = &IpvsConf{}
	gIpvsLbInfoMap = make(map[string]map[string]LbInfo)

	// add ipvs-log, ipvs-full-nat to nat table postrouting chain,
	// ipvs log must be ahead of ipvs-full-nat
	table := utils.NewIpTables(utils.NatTable)
	table.AddChain(IPVS_LOG_CHAIN_NAME)
	table.AddChain(IPVS_FULL_NAT_CHAIN_NAME)

	rule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
	rule.SetIpvs(true)
	rule.SetAction(IPVS_LOG_CHAIN_NAME).SetCompareTarget(true)
	table.AddIpTableRules([]*utils.IpTableRule{rule})

	rule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
	rule.SetIpvs(true)
	rule.SetAction(IPVS_FULL_NAT_CHAIN_NAME).SetCompareTarget(true)
	table.AddIpTableRules([]*utils.IpTableRule{rule})

	err := table.Apply()
	utils.PanicOnError(err)

	if utils.IsEuler2203() {
		utils.ServiceOperation("ipvsHealthCheck", "restart")
	} else {
		startIpvsHealthCheckPidMon()
	}

	bash := utils.Bash{
		Command: fmt.Sprintf("sysctl -w net.ipv4.vs.conntrack=1"),
		Sudo:    true,
	}
	bash.Run()
	bash.PanicIfError()
}
