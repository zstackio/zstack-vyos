package plugin

import "zvr/server"

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
	return nil
}

func pingHandler(ctx *server.CommandContext) interface{} {
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

