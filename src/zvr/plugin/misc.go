package plugin

import "zvr"

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

func initHandler(ctx *zvr.CommandContext) interface{} {
	ctx.GetCommand(initConfig)
	return nil
}

func pingHandler(ctx *zvr.CommandContext) interface{} {
	return pingRsp{ Uuid: initConfig.Uuid }
}

func echoHandler(ctx *zvr.CommandContext) interface{} {
	return nil
}

func init()  {
	zvr.RegisterAsyncCommandHandler(INIT_PATH, initHandler)
	zvr.RegisterAsyncCommandHandler(PING_PATH, pingHandler)
	zvr.RegisterSyncCommandHandler(ECHO_PATH, echoHandler)
}

func GetInitConfig() *InitConfig {
	return initConfig
}
