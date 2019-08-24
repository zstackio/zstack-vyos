package plugin

import (
	"zvr/server"
	"zvr/utils"
	log "github.com/Sirupsen/logrus"
	"fmt"
	"io/ioutil"
	"time"
)

const (
	INIT_PATH = "/init"
	PING_PATH = "/ping"
	ECHO_PATH = "/echo"
	/* please follow following rule to change the version:
	  http://confluence.zstack.io/pages/viewpage.action?pageId=34014178 */
	VERSION_FILE_PATH = "/home/vyos/zvr/version"
)

var (
	VERSION = ""
)

type InitConfig struct {
	RestartDnsmasqAfterNumberOfSIGUSER1 int `json:"restartDnsmasqAfterNumberOfSIGUSER1"`
	Uuid string `json:"uuid"`
}

/*
the current health of whole system
*/
type HealthStatus struct {
	Healthy bool `json:"healthy"`
	HealthDetail string `json:"healthDetail"`
}

type pingRsp struct {
	Uuid string `json:"uuid"`
	Version string `json:"version"`
	HaStatus string `json:"haStatus"`
	Healthy bool `json:"healthy"`
	HealthDetail string `json:"healthDetail"`
}

var (
	initConfig = &InitConfig{}
	healthStatus = &HealthStatus{Healthy:true, HealthDetail:""}
)

func (status *HealthStatus) healthCheck() {
	bash := utils.Bash{
		Command: "sudo mount|grep -w ro",
	}
	if ret, output, _, err := bash.RunWithReturn(); err == nil && ret == 0 {
		status.Healthy = false
		status.HealthDetail = fmt.Sprintf("RO file system: %s", output)
	} else if !status.Healthy{
		status.Healthy = true
		status.HealthDetail = ""
	}
}

func initHandler(ctx *server.CommandContext) interface{} {
	ctx.GetCommand(initConfig)
	addRouteIfCallbackIpChanged()
	return nil
}

func pingHandler(ctx *server.CommandContext) interface{} {

	addRouteIfCallbackIpChanged()
	var haStatus string
	if !utils.IsHaEabled() {
		haStatus = utils.NOHA
	} else if IsMaster() {
		haStatus = utils.HAMASTER
	} else {
		haStatus = utils.HABACKUP
	}
	return pingRsp{Uuid: initConfig.Uuid, Version: string(VERSION), HaStatus: haStatus,
		Healthy:healthStatus.Healthy, HealthDetail:healthStatus.HealthDetail }
}

func echoHandler(ctx *server.CommandContext) interface{} {
	return nil
}

func MiscEntryPoint() {
	server.RegisterAsyncCommandHandler(INIT_PATH, initHandler)
	server.RegisterAsyncCommandHandler(PING_PATH, pingHandler)
	server.RegisterSyncCommandHandler(ECHO_PATH, echoHandler)
}

func GetInitConfig() *InitConfig {
	return initConfig
}

func addRouteIfCallbackIpChanged() {
	if server.CURRENT_CALLBACK_IP != server.CALLBACK_IP {
		if server.CURRENT_CALLBACK_IP == "" {
			log.Debug(fmt.Sprintf("agent first start, add static route to callback ip host"))
		} else {
			log.Debug(fmt.Sprintf("detect call back ip host changed, add static route"))
		}
		// NOTE(WeiW): Since our mgmt nic is always eth0
		if server.CURRENT_CALLBACK_IP != "" {
			err := utils.RemoveZStackRoute(server.CURRENT_CALLBACK_IP);
			utils.PanicOnError(err)
		}

		mgmtNic := utils.GetMgmtInfoFromBootInfo()
		if (mgmtNic == nil || utils.CheckMgmtCidrContainsIp(server.CALLBACK_IP, mgmtNic) == false) {
			err := utils.SetZStackRoute(server.CALLBACK_IP, "eth0", mgmtNic["gateway"].(string)); utils.PanicOnError(err)
		} else if mgmtNic == nil {
			log.Debugf("can not get mgmt nic info, skip to configure route")
		} else if utils.GetNicForRoute(server.CALLBACK_IP) != "eth0" {
			err := utils.SetZStackRoute(server.CALLBACK_IP, "eth0", ""); utils.PanicOnError(err)
		} else {
			log.Debugf("the cidr of vr mgmt contains callback ip, skip to configure route")
		}
		server.CURRENT_CALLBACK_IP = server.CALLBACK_IP
	}
}

func init ()  {
	ver, err := ioutil.ReadFile(VERSION_FILE_PATH)
	if err == nil {
		VERSION = string(ver)
	}

	go func() {
		for {
			healthStatus.healthCheck()
			time.Sleep(time.Duration(60 * time.Second))
		}
	} ()
}
