package plugin

import (
	"zvr/server"
	"zvr/utils"
	log "github.com/Sirupsen/logrus"
	"fmt"
	"io/ioutil"
	"encoding/json"
)

const (
	INIT_PATH = "/init"
	PING_PATH = "/ping"
	ECHO_PATH = "/echo"
	/* please follow following rule to change the version:
	  http://confluence.zstack.io/pages/viewpage.action?pageId=34014178 */
	VERSION_FILE_PATH = "/home/vyos/zvr/version"
)

type InitConfig struct {
	RestartDnsmasqAfterNumberOfSIGUSER1 int `json:"restartDnsmasqAfterNumberOfSIGUSER1"`
	Uuid string `json:"uuid"`
}

type pingRsp struct {
	Uuid string `json:"uuid"`
	Version string `json:"version"`
}

var (
	initConfig = &InitConfig{}
)

func initHandler(ctx *server.CommandContext) interface{} {
	ctx.GetCommand(initConfig)
	addRouteIfCallbackIpChanged()
	return nil
}

func pingHandler(ctx *server.CommandContext) interface{} {
	addRouteIfCallbackIpChanged()
	version, err := ioutil.ReadFile(VERSION_FILE_PATH)
	if err != nil {
		version = []byte("")
	}

	return pingRsp{ Uuid: initConfig.Uuid, Version: string(version) }
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

		mgmtNic := getMgmtInfoFromBootInfo()
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



func getMgmtInfoFromBootInfo() map[string]interface{} {
	content, err := ioutil.ReadFile(BOOTSTRAP_INFO_CACHE); utils.PanicOnError(err)
	if len(content) == 0 {
		log.Debugf("no content in %s, can not get mgmt gateway", BOOTSTRAP_INFO_CACHE)
		return nil
	}

	if err := json.Unmarshal(content, &bootstrapInfo); err != nil {
		log.Debugf("can not parse info from %s, can not get mgmt gateway", BOOTSTRAP_INFO_CACHE)
		return nil
	}

	mgmtNic := bootstrapInfo["managementNic"].(map[string]interface{})
	return mgmtNic
}
