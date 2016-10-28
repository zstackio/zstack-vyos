package plugin

import "zvr/server"

const (
	CREATE_PORT_FORWARDING_PATH = "/createportforwarding"
	REVOKE_PORT_FORWARDING_PATH = "/revokeportforwarding"
	SYNC_PORT_FORWARDING_PATH = "/syncportforwarding"
)

type dnatInfo struct {
	VipPortStart int `json:"vipPortStart"`
	VipPortEnd int `json:"vipPortEnd"`
	PrivatePortStart int `json:"privatePortStart"`
	PrivatePortEnd int `json:"privatePortEnd"`
	ProtocolType string `json:"protocolType"`
	VipIp string `json:"vipIp"`
	PrivateIp string `json:"privateIp"`
	PrivateMac string `json:"privateMac"`
	AllowedCidr string `json:"allowedCidr"`
	SnatInboundTraffic bool `json:"snatInboundTraffic"`
}

type setDnatCmd struct {
	Rules []dnatInfo `json:"rules"`
}

type removeDnatCmd struct {
	Rules []dnatInfo `json:"rules"`
}

type syncDnatCmd struct {
	Rules []dnatInfo `json:"rules"`
}

func syncDnatHandler(ctx *server.CommandContext) interface{} {
	return nil
}

func setDnatHandler(ctx *server.CommandContext) interface{} {
	return nil
}

func removeDnatHandler(ctx *server.CommandContext) interface{} {
	return nil
}

func DnatEntryPoint() {
	server.RegisterAsyncCommandHandler(CREATE_PORT_FORWARDING_PATH, server.VyosLock(setDnatHandler))
	server.RegisterAsyncCommandHandler(REVOKE_PORT_FORWARDING_PATH, server.VyosLock(removeDnatHandler))
	server.RegisterAsyncCommandHandler(SYNC_PORT_FORWARDING_PATH, server.VyosLock(syncDnatHandler))
}
