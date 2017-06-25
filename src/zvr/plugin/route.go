package plugin

import (
	"zvr/server"
	"zvr/utils"
	"fmt"
	"github.com/pkg/errors"
)

const (
	SYNC_ROUTES = "/syncroutes"
	GET_ROUTES = "/getroutes"
)

type routeInfo struct {
	Destination string `json:"destination"`
	Target      string `json:"target"`
	Distance      int `json:"distance"`
}

type SyncRoutesCmd struct {
	Routes []routeInfo `json:"routes"`
}

type GetRoutesRsp struct {
	RawRoutes string `json:"rawRoutes"`
}

func syncRoutes(ctx *server.CommandContext) interface{} {
	cmd := &SyncRoutesCmd{}
	ctx.GetCommand(cmd)

	setRoutes(cmd.Routes)
	return nil
}

func setRoutes(infos []routeInfo) {
	tree := server.NewParserFromShowConfiguration().Tree
	if rs := tree.Get("protocols static route"); rs != nil {
		for _, r := range rs.Children() {
			r.Delete()
		}
	}

	for _, route := range infos {
		if route.Target == "" {
			tree.Setf("protocols static route %s blackhole distance %d", route.Destination, route.Distance)
		} else {
			tree.Setf("protocols static route %s next-hop %s distance %d", route.Destination, route.Target, route.Distance)
		}
	}

	tree.Apply(false)
}

func getRoutes(ctx *server.CommandContext) interface{} {
	// Note(WeiW): add "vtysh -c "show ip route " >/dev/null" to get correct return code
	bash := utils.Bash {
		Command: fmt.Sprintf("vtysh -c 'show ip route' | tail -n +4; vtysh -c 'show ip route' >/dev/null"),
	}
	ret, o, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
	if ret != 0 {
		utils.PanicOnError(errors.Errorf(("get route from zebra error")))
	}
	return GetRoutesRsp{ RawRoutes: o }
}

func RouteEntryPoint()  {
	server.RegisterAsyncCommandHandler(SYNC_ROUTES, server.VyosLock(syncRoutes))
	server.RegisterAsyncCommandHandler(GET_ROUTES, server.VyosLock(getRoutes))
}