package plugin

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"strconv"
	"zvr/server"
	"zvr/utils"
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

func getCurrentStaticRoutes(tree *server.VyosConfigTree) (routes []routeInfo) {
	var infos []routeInfo
	rnode := tree.Get("protocols static route")
	for _, r := range rnode.Children() {
		nhop := r.Get("next-hop")
		if nhop != nil {
			for _, n := range nhop.Children() {
				dis := n.GetChildrenValue("distance")
				distance, _ := strconv.Atoi(dis)
				var info = routeInfo{Destination:r.Name(), Target: n.Name(), Distance: distance}
				infos = append(infos, info)
			}
		}

		bh := r.Get("blackhole")
		if bh != nil {
			dis := bh.GetChildrenValue("distance")
			distance, _ := strconv.Atoi(dis)
			var info = routeInfo{Destination:r.Name(), Target: "", Distance: distance}
			infos = append(infos, info)
		}
	}
	return infos
}

func setRoutes(infos []routeInfo) {
	tree := server.NewParserFromShowConfiguration().Tree
	oldStaticRoutes := getCurrentStaticRoutes(tree)
	log.Debugf("old static routes: %+v", oldStaticRoutes)
	for _, route := range infos {
		if route.Target == "" {
			tree.Setf("protocols static route %s blackhole distance %d", route.Destination, route.Distance)
		} else {
			tree.Setf("protocols static route %s next-hop %s distance %d", route.Destination, route.Target, route.Distance)
		}
	}

	for _, o := range oldStaticRoutes {
		if o.Destination == "0.0.0.0/0" {
			continue
		}
		delete := true
		for _, r := range infos {
			if r.Destination == o.Destination && r.Target == o.Target {
				delete = false
				break
			}
		}
		if delete {
			log.Debugf("delete old route: %+v", o)
			tree.Deletef("protocols static route %s", o.Destination)
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
