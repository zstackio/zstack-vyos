package plugin

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	log "github.com/sirupsen/logrus"
)

const (
	INIT_PATH          = "/init"
	PING_PATH          = "/ping"
	ECHO_PATH          = "/echo"
	TYPE_PATH          = "/type"
	TEST_PATH          = "/test"
	CONFIGURE_NTP_PATH = "/configurentp"
	NTPD_CONFIG_FILE   = "/etc/ntp.conf"
	CHRONYD_CONFIG_FILE   = "/etc/chrony.conf"
)

var (
	/* please follow following rule to change the version:
	   http://confluence.zstack.io/pages/viewpage.action?pageId=34014178 */
	VERSION                    = ""
)

func getVersionFilePath() string {
	return filepath.Join(utils.GetZvrRootPath(), "version")
}
func getNetworlHealthStatusPath() string {
	return filepath.Join(utils.GetZvrRootPath(), ".duplicate")
}
func getNtpConfDir() string {
	return filepath.Join(utils.GetZvrRootPath(), "ntp/conf/")
}

type InitConfig struct {
	RestartDnsmasqAfterNumberOfSIGUSER1 int               `json:"restartDnsmasqAfterNumberOfSIGUSER1"`
	Uuid                                string            `json:"uuid"`
	MgtCidr                             string            `json:"mgtCidr"`
	LogLevel                            string            `json:"logLevel"`
	TimeServers                         []string          `json:"timeServers"`
	Parms                               map[string]string `json:"parms"`
}

type initRsp struct {
	Uuid          string `json:"uuid"`
	ZvrVersion    string `json:"zvrVersion"`
	VyosVersion   string `json:"vyosVersion"`
	KernelVersion string `json:"kernelVersion"`
	//ServiceStatus []*ServiceStatus `json:"serviceStatus"`
	IpsecCurrentVersion string `json:"ipsecCurrentVersion"`
	IpsecLatestVersion  string `json:"ipsecLatestVersion"`
}

type ServiceStatus struct {
	ServiceName     string   `json:"currentVersion"`
	CurrentVersion  string   `json:"currentVersion"`
	LatestVersion   string   `json:"latestVersion"`
	SupportVersions []string `json:"supportVersions"`
	// status string `json:"uuid"`
}

type pingRsp struct {
	Uuid              string                       `json:"uuid"`
	Version           string                       `json:"version"`
	HaStatus          string                       `json:"haStatus"`
	Healthy           bool                         `json:"healthy"`
	HealthDetail      string                       `json:"healthDetail"`
	ServiceHealthList map[string]map[string]string `json:"serviceHealthList"`
}

type typeRsp struct {
	Success bool `json:"success"`
	IsVyos  bool `json:"isVyos"`
}

type testRsp struct {
	Success    bool   `json:"success"`
	ZvrVersion string `json:"zvrVersion"`
}

type configureNtpCmd struct {
	TimeServers []string `json:"timeServers"`
}

var (
	initConfig = &InitConfig{}
)

type networkHealthCheck struct{}
type fsHealthCheck struct{}

func (check *networkHealthCheck) healthCheck() (status HealthStatus) {
	status = HealthStatus{Healthy: true, HealthDetail: ""}
	if e, _ := utils.PathExists(getNetworlHealthStatusPath()); e {
		f, _ := ioutil.ReadFile(getNetworlHealthStatusPath())
		status.Healthy = false
		status.HealthDetail = string(f)
	}

	return status
}

func (check *fsHealthCheck) healthCheck() (status HealthStatus) {
	bash := utils.Bash{
		Command: "mount | grep -w ro | grep -v ^/dev/loop | grep -vw tmpfs",
		NoLog:   true,
	}
	status = HealthStatus{Healthy: true, HealthDetail: ""}
	if ret, output, _, err := bash.RunWithReturn(); err == nil && ret == 0 {
		status.Healthy = false
		status.HealthDetail = fmt.Sprintf("RO file system: %s", output)
	}
	return status
}

func configure(parms map[string]string) {
	if value, exist := parms["ipv4LocalPortRange"]; exist {
		if strings.Count(value, "-") == 1 {
			port := strings.Split(value, "-")

			lowPort, error := strconv.Atoi(port[0])
			if error != nil {
				log.Errorf("configure ipv4LocalPortRange fail beacuse %s", error)
				return
			}

			upPort, error := strconv.Atoi(port[1])
			if error != nil {
				log.Errorf("configure ipv4LocalPortRange fail beacuse %s", error)
				return
			}

			if (lowPort < 0 || upPort > 65535 || upPort < lowPort) || (lowPort > 0 && lowPort < 1024) {
				log.Errorf("port is not in range [1024,65535],port range %s-%s, ", port[0], port[1])
				return
			}

			if lowPort == 0 || upPort == 0 {
				log.Debugf("no need to set ip_local_port_range beacause port contain 0, port range %s-%s, ", port[0], port[1])
			} else {
				bash := utils.Bash{
					Command: fmt.Sprintf("sudo sysctl -w net.ipv4.ip_local_port_range='%s %s'", port[0], port[1]),
				}
				bash.Run()
				bash.PanicIfError()
			}
		}
	}
}

func configChronyd(timeServers []string) {
	var conf bytes.Buffer
	conf.WriteString(`
# Created by ZStack, DO NOT MODIFY IT
# Use public servers from the pool.ntp.org project.
# Please consider joining the pool (http://www.pool.ntp.org/join.html).
#server 0.centos.pool.ntp.org iburst
#server 1.centos.pool.ntp.org iburst
#server 2.centos.pool.ntp.org iburst
#server 3.centos.pool.ntp.org iburst

# Record the rate at which the system clock gains/losses time.
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
# if its offset is larger than 1 second.
makestep 1.0 3

# Enable kernel synchronization of the real-time clock (RTC).
rtcsync

# Enable hardware timestamping on all interfaces that support it.
#hwtimestamp *

# Increase the minimum number of selectable sources required to adjust
# the system clock.
#minsources 2

# Allow NTP client access from local network.
#allow 192.168.0.0/16

# Serve time even if not synchronized to a time source.
#local stratum 10

# Specify file containing keys for NTP authentication.
#keyfile /etc/chrony.keys

# Specify directory for log files.
logdir /var/log/chrony

# Select which information is logged.
#log measurements statistics tracking
local stratum 10
allow 0.0.0.0/0
`)

	for _, chronyServer := range timeServers {
		conf.WriteString("server " + chronyServer + " iburst\n")
	}

	err := os.WriteFile(CHRONYD_CONFIG_FILE, conf.Bytes(), 0644)
	utils.PanicOnError(err)
	utils.ServiceOperation("chronyd", "restart")
}

func configureNtp(timeServers []string) {
	if timeServers == nil || len(timeServers) == 0 {
		return
	}

	if utils.Vyos_version == utils.EULER_22_03 {
		configChronyd(timeServers)
		return;
	}
	
	var conf bytes.Buffer
	conf.WriteString(`# /etc/ntp.conf, configuration for ntpd; see ntp.conf(5) for help
# This configuration file is automatically generated by the Vyatta
# configuration subsystem.  Please do not manually edit it.
#
# The first section of this file consists of static parameters
# that can not be changed via the Vyatta configuration subsystem.
#
driftfile /var/lib/ntp/ntp.drift
# By default, exchange time with everybody, but don't allow configuration.
restrict -4 default kod notrap nomodify nopeer noquery
restrict -6 default kod notrap nomodify nopeer noquery
# Local users may interrogate the ntp server more closely.

restrict 127.0.0.1
restrict ::1

# Listen local ports only
interface ignore wildcard
interface listen 127.0.0.1
interface listen ::1

#
# The remainder of this file is for parameters that are set up via
# the Vyatta configuration subsystem.
#

`)

	for _, chronyServer := range timeServers {
		conf.WriteString("server " + chronyServer + "\n")
	}

	ntp_conf_file, err := ioutil.TempFile(getNtpConfDir(), "ntpConfig")
	utils.PanicOnError(err)
	_, err = ntp_conf_file.Write(conf.Bytes())
	utils.PanicOnError(err)

	err = utils.SudoMoveFile(ntp_conf_file.Name(), NTPD_CONFIG_FILE)
	utils.PanicOnError(err)

	err = utils.ServiceOperation("ntpd", "restart")
	utils.PanicOnError(err)
}

func configTaskScheduler() {
	if !utils.IsEnableVyosCmd() {
		sshJob := utils.NewCronjob().SetId(1).SetCommand(utils.GetCronjobFileSsh()).SetMinute("*/1")
		zvrMonitorJob := utils.NewCronjob().SetId(2).SetCommand(utils.GetCronjobFileZvrMonitor()).SetMinute("*/1")
		fileMonitorJob := utils.NewCronjob().SetId(3).SetCommand(fmt.Sprintf("/usr/bin/flock -xn /tmp/file-monitor.lock -c %s", utils.GetCronjobFileMonitor())).SetMinute("0").SetHour("*/1")
		rsyslogJob := utils.NewCronjob().SetId(4).SetCommand(utils.GetCronjobFileRsyslog()).SetMinute("*/1")
		
		cronJobMap := utils.CronjobMap{
			2: zvrMonitorJob,
			3: fileMonitorJob,
		}

		if !utils.IsEuler2203() {
			cronJobMap[1] = sshJob
			cronJobMap[4] = rsyslogJob
		}

		err := cronJobMap.ConfigService()
		utils.PanicOnError(err)
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		if tree.Get("system task-scheduler task ssh") != nil {
			tree.Delete("system task-scheduler task ssh")
		}
		if tree.Get("system task-scheduler task ssh") == nil {
			tree.Set("system task-scheduler task ssh interval 1")
			tree.Set(fmt.Sprintf("system task-scheduler task ssh executable path '%s'", utils.GetCronjobFileSsh()))
		}
		if tree.Get("system task-scheduler task rsyslog") == nil {
			tree.Set("system task-scheduler task rsyslog interval 1")
			tree.Set(fmt.Sprintf("system task-scheduler task rsyslog executable path '%s'", utils.GetCronjobFileRsyslog()))
		}
		if tree.Get("system task-scheduler task zvr-monitor") == nil {
			tree.Set("system task-scheduler task zvr-monitor interval 1")
			tree.Set(fmt.Sprintf("system task-scheduler task zvr-monitor executable path '%s'", utils.GetCronjobFileZvrMonitor()))
		}
		/*
		if tree.Get("system task-scheduler task cpu-monitor") == nil {
			tree.Set("system task-scheduler task cpu-monitor interval 1")
			tree.Set("system task-scheduler task cpu-monitor executable path /usr/bin/top")
			tree.Set("system task-scheduler task cpu-monitor executable arguments '-b -n 1 -H >> /var/log/top.log'")
		} */
		if tree.Get("system task-scheduler task file-monitor") == nil {
			tree.Set("system task-scheduler task file-monitor interval 1h")
			tree.Set("system task-scheduler task file-monitor executable path /usr/bin/flock")
			tree.Set(fmt.Sprintf("system task-scheduler task file-monitor executable arguments '-xn /tmp/file-monitor.lock -c %s'", utils.GetCronjobFileMonitor()))
		}

		tree.Apply(false)
	}
}

func initHandler(ctx *server.CommandContext) interface{} {
	ctx.GetCommand(initConfig)
	addRouteIfCallbackIpChanged(true)
	if initConfig.MgtCidr != "" {
		mgmtNic := utils.GetMgmtInfoFromBootInfo()
		nexthop, _ := utils.GetNexthop(initConfig.MgtCidr)
		if nexthop != mgmtNic["gateway"].(string) {
			utils.AddRoute(initConfig.MgtCidr, mgmtNic["gateway"].(string))
		}
	}

	configTaskScheduler()
	doRefreshLogLevel(initConfig.LogLevel)
	configureNtp(initConfig.TimeServers)
	configure(initConfig.Parms)

	strongswanCurrentVersion, strongswanLatestVersion := GetIpsecVersionInfo()
	return initRsp{Uuid: initConfig.Uuid, ZvrVersion: VERSION, VyosVersion: utils.Vyos_version,
		KernelVersion:       utils.Kernel_version,
		IpsecCurrentVersion: strongswanCurrentVersion, IpsecLatestVersion: strongswanLatestVersion}
}

func setServiceStatus() []*ServiceStatus {
	var serviceList []*ServiceStatus
	// get all service status infomation
	serviceList = append(serviceList, GetIpsecServiceStatus())
	return serviceList
}

func pingHandler(ctx *server.CommandContext) interface{} {
	serviceHealthList := make(map[string]map[string]string)
	serviceHealthList[IPSEC_STATUS_NAME] = getIpsecConnsState()
	
	addRouteIfCallbackIpChanged(false)
	
	var haStatus string
	if !utils.IsHaEnabled() {
		haStatus = utils.NOHA
	} else if IsMaster() {
		haStatus = utils.HAMASTER
	} else {
		haStatus = utils.HABACKUP
	}

	return pingRsp{Uuid: initConfig.Uuid, Version: string(VERSION), HaStatus: haStatus,
		Healthy: healthStatus.Healthy, HealthDetail: healthStatus.HealthDetail,
		ServiceHealthList: serviceHealthList}
}

func echoHandler(ctx *server.CommandContext) interface{} {
	return nil
}

func typeHandler(ctx *server.CommandContext) interface{} {
	return typeRsp{IsVyos: utils.IsVYOS(), Success: true}
}

func testHandler(ctx *server.CommandContext) interface{} {
	return testRsp{ZvrVersion: string(VERSION), Success: true}
}

func configureNtpHandle(ctx *server.CommandContext) interface{} {
	cmd := &configureNtpCmd{}
	ctx.GetCommand(cmd)

	configureNtp(cmd.TimeServers)
	return nil
}
func MiscEntryPoint() {
	server.RegisterAsyncCommandHandler(INIT_PATH, server.VyosLock(initHandler))
	server.RegisterAsyncCommandHandler(PING_PATH, pingHandler)
	server.RegisterSyncCommandHandler(ECHO_PATH, echoHandler)
	server.RegisterSyncCommandHandler(TYPE_PATH, typeHandler)
	server.RegisterSyncCommandHandler(TEST_PATH, server.VyosLock(testHandler))
	server.RegisterAsyncCommandHandler(CONFIGURE_NTP_PATH, configureNtpHandle)
}

func GetInitConfig() *InitConfig {
	return initConfig
}

func addRouteIfCallbackIpChanged(init bool) {

	update := false
	if server.CURRENT_CALLBACK_IP != server.CALLBACK_IP {
		update = true
	} else if init {
		// for reconnect
		if !utils.CheckZStackRouteExists(server.CALLBACK_IP) {
			update = true
		}
	}

	if update {
		if server.CURRENT_CALLBACK_IP == "" {
			log.Debug(fmt.Sprintf("agent first start, add static route to callback ip host"))
		} else {
			log.Debug(fmt.Sprintf("detect call back ip host changed, add static route"))
		}
		// NOTE(WeiW): Since our mgmt nic is always eth0
		if server.CURRENT_CALLBACK_IP != "" {
			err := utils.RemoveZStackRoute(server.CURRENT_CALLBACK_IP)
			utils.PanicOnError(err)
		}

		mgmtNic := utils.GetMgmtInfoFromBootInfo()
		if mgmtNic != nil && utils.CheckMgmtCidrContainsIp(server.CALLBACK_IP, mgmtNic) == false {
			err := utils.SetZStackRoute(server.CALLBACK_IP, "eth0", mgmtNic["gateway"].(string))
			utils.PanicOnError(err)
		} else if mgmtNic == nil {
			log.Debugf("can not get mgmt nic info, skip to configure route")
		} else if utils.GetNicForRoute(server.CALLBACK_IP) != "eth0" {
			err := utils.SetZStackRoute(server.CALLBACK_IP, "eth0", "")
			utils.PanicOnError(err)
		} else {
			log.Debugf("the cidr of vr mgmt contains callback ip, skip to configure route")
		}
		server.CURRENT_CALLBACK_IP = server.CALLBACK_IP
	}
}

func InitMisc() {
	os.MkdirAll(getNtpConfDir(), os.ModePerm)
	ver, err := os.ReadFile(getVersionFilePath())
	if err == nil {
		VERSION = strings.TrimSpace(string(ver))
	}
	RegisterHealthCheckCallback(&fsHealthCheck{})
	RegisterHealthCheckCallback(&networkHealthCheck{})
}
