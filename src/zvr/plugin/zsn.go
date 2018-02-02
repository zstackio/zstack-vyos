package plugin

import (
	"zvr/server"
	"fmt"
	"io/ioutil"
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"net/http"
	"time"
)

const (
	ZSN_SET_DR_PATH = "/zsn/dr"
	ZSN_STATUS_PATH = "/zsn/status"
	ZSN_CONNECTION_PATH = "/zsn/connections"

	zsn_status_uri = "/"
	zsn_connection_uri = "/conn"
	zsn_enable_uri = "/enable"
	zsn_disable_uri = "/disable"
)

type setDistributedRoutingReq struct {
	Enabled bool `json:"enabled"`
}

type zsnAgent struct {
	addr string
}

func (z zsnAgent) init(uri string) string {
	z.addr = "http://127.0.0.1:7274"
	client := http.Client{Timeout:2*time.Second}
	addr := fmt.Sprintf("%s%s", z.addr, uri)

	rsp, err := client.Get(addr)
	if err != nil {
		log.Warnf("get error from client %v", err)
		return ""
	}
	defer rsp.Body.Close()
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		log.Warnf("get error in body read %v", err)
		return ""
	}
	log.Debugf("addr: %s, body: %s", addr, body)

	return fmt.Sprintf("%s", body)
}

func (z zsnAgent) getStatus() string {
	return z.init(zsn_status_uri)
}

func (z zsnAgent) getConnections() string {
	return z.init(zsn_connection_uri)
}

func (z zsnAgent) enable() string {
	return z.init(zsn_enable_uri)
}

func (z zsnAgent) disable() string {
	return z.init(zsn_disable_uri)
}

type getStatusRsp struct {
	RawStatus string `json:"rawStatus"`
}

type getConnRsp struct {
	RawConnections string `json:"rawConnections"`
}

type setDistributedRoutingRsp struct {
	Enabled string `json:"enabled"`
}

type zsnsetDistributedRoutingRsp struct {
	DistributedRouting string
}

func getStatus(ctx *server.CommandContext) interface{} {
	z := zsnAgent{}
	return getStatusRsp{ RawStatus:z.getStatus() }
}

func getConnections(ctx *server.CommandContext) interface{} {
	z := zsnAgent{}
	return getConnRsp{ RawConnections:z.getConnections() }
}

func setDistributedRouting(ctx *server.CommandContext) interface{} {
	cmd := &setDistributedRoutingReq{}
	ctx.GetCommand(cmd)

	var r string
	var z zsnAgent
	t := &zsnsetDistributedRoutingRsp{}

	if cmd.Enabled {
		r = z.enable()
	} else {
		r = z.disable()
	}

	err := json.Unmarshal([]byte(r), &t)
	if  err != nil {
		log.Warnf("can not unmarshal json from %s, return empty", r)
		return setDistributedRoutingRsp{}
	}

	if t.DistributedRouting == "true" {
		return setDistributedRoutingRsp{Enabled:"true"}
	} else {
		return setDistributedRoutingRsp{Enabled:"false"}
	}
}

func ZsnEntryPoint()  {
	server.RegisterAsyncCommandHandler(ZSN_SET_DR_PATH, setDistributedRouting)
	server.RegisterAsyncCommandHandler(ZSN_STATUS_PATH, getStatus)
	server.RegisterAsyncCommandHandler(ZSN_CONNECTION_PATH, getConnections)
}