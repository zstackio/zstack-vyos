package plugin

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"zstack-vyos/server"
	"zstack-vyos/utils"
)

const (
	ZSN_SET_DR_PATH     = "/zsn/dr"
	ZSN_STATUS_PATH     = "/zsn/status"
	ZSN_CONNECTION_PATH = "/zsn/connections"

	zsn_status_uri     = "/"
	zsn_connection_uri = "/conn"
	zsn_enable_uri     = "/enable"
	zsn_disable_uri    = "/disable"

	zsn_state_file         = "/tmp/dr"
	ZSN_STATE_FILE_DISABLE = "-960"
	ZSN_STATE_FILE_ENABLE  = "960"
)

type setDistributedRoutingReq struct {
	Enabled bool `json:"enabled"`
}

type zsnAgent struct {
	addr string
}

func (z zsnAgent) init(uri string) string {
	z.addr = "http://127.0.0.1:7274"
	client := http.Client{Timeout: 2 * time.Second}
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
	return getStatusRsp{RawStatus: z.getStatus()}
}

func getConnections(ctx *server.CommandContext) interface{} {
	z := zsnAgent{}
	return getConnRsp{RawConnections: z.getConnections()}
}

func setDistributedRouting(cmd *setDistributedRoutingReq) interface{} {
	var r string
	var z zsnAgent
	t := &zsnsetDistributedRoutingRsp{}

	fd, _ := utils.CreateFileIfNotExists(zsn_state_file, os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	defer fd.Close()
	fd.Truncate(0)

	if !utils.IsEnableVyosCmd() {
		if cmd.Enabled {
			r = z.enable()
			fd.Write([]byte(ZSN_STATE_FILE_ENABLE))
			zsnJob := utils.NewCronjob().SetId(6).SetCommand(utils.Cronjob_file_zsn).SetMinute("*/1")
			cronJobMap := utils.CronjobMap{6: zsnJob}
			err := cronJobMap.ConfigService()
			utils.PanicOnError(err)
		} else {
			r = z.disable()
			fd.Write([]byte(ZSN_STATE_FILE_DISABLE))
			zsnJob := utils.NewCronjob().SetId(6).SetCommand(utils.Cronjob_file_zsn).SetMinute("*/1").SetDelete()
			cronJobMap := utils.CronjobMap{6: zsnJob}
			err := cronJobMap.ConfigService()
			utils.PanicOnError(err)
		}
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		if cmd.Enabled {
			r = z.enable()
			fd.Write([]byte(ZSN_STATE_FILE_ENABLE))

			if node := tree.Get("system task-scheduler task zsn interval 1"); node == nil {
				/* create a cronjob to check zsn */
				tree.Set("system task-scheduler task zsn interval 1")
				tree.Set(fmt.Sprintf("system task-scheduler task zsn executable path '%s'", utils.Cronjob_file_zsn))
			}
		} else {
			r = z.disable()
			fd.Write([]byte(ZSN_STATE_FILE_DISABLE))

			tree.Delete("system task-scheduler task zsn")
		}

		tree.Apply(false)
	}

	err := json.Unmarshal([]byte(r), &t)
	if err != nil {
		log.Warnf("can not unmarshal json from %s, return empty", r)
		return setDistributedRoutingRsp{}
	}

	if t.DistributedRouting == "true" {
		return setDistributedRoutingRsp{Enabled: "true"}
	} else {
		return setDistributedRoutingRsp{Enabled: "false"}
	}
}

func setDistributedRoutingHandler(ctx *server.CommandContext) interface{} {
	cmd := &setDistributedRoutingReq{}
	ctx.GetCommand(cmd)

	return setDistributedRouting(cmd)
}

func ZsnEntryPoint() {
	server.RegisterAsyncCommandHandler(ZSN_SET_DR_PATH, server.VyosLock(setDistributedRoutingHandler))
	server.RegisterAsyncCommandHandler(ZSN_STATUS_PATH, getStatus)
	server.RegisterAsyncCommandHandler(ZSN_CONNECTION_PATH, getConnections)
}
