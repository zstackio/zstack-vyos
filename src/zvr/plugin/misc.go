package plugin

import (
	"zvr/server"
	"zvr/utils"
	log "github.com/Sirupsen/logrus"
	"fmt"
)

const (
	INIT_PATH = "/init"
	PING_PATH = "/ping"
	ECHO_PATH = "/echo"
)

type InitConfig struct {
	RestartDnsmasqAfterNumberOfSIGUSER1 int `json:"restartDnsmasqAfterNumberOfSIGUSER1"`
	Uuid string `json:"uuid"`
}

type pingRsp struct {
	Uuid string `json:"uuid"`
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
	return pingRsp{ Uuid: initConfig.Uuid }
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
			err := utils.RemoveZStackRoute(server.CURRENT_CALLBACK_IP, "eth0");
			utils.PanicOnError(err)
		}
		err := utils.SetZStackRoute(server.CALLBACK_IP, "eth0"); utils.PanicOnError(err)
		server.CURRENT_CALLBACK_IP = server.CALLBACK_IP
	}
}

