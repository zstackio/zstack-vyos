package plugin

import (
	"fmt"
	"strconv"
	"strings"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	SYNC_ROUTES = "/syncroutes"
	GET_ROUTES  = "/getroutes"
)

type routeInfo struct {
	Destination string `json:"destination"`
	Target      string `json:"target"`
	Distance    int    `json:"distance"`
}

type SyncRoutesCmd struct {
	Routes []routeInfo `json:"routes"`
}

type GetRoutesRsp struct {
	RawRoutes string `json:"rawRoutes"`
}

type routeArray []routeInfo

func (a routeArray) Len() int      { return len(a) }
func (a routeArray) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a routeArray) Less(i, j int) bool {
	if a[i].Destination != a[j].Destination {
		return strings.Compare(a[i].Destination, a[j].Destination) > 0
	} else if a[i].Target != a[j].Target {
		return strings.Compare(a[i].Target, a[j].Target) > 0
	} else {
		return a[i].Distance >= a[j].Distance
	}
}

func syncRoutes(ctx *server.CommandContext) interface{} {
	cmd := &SyncRoutesCmd{}
	ctx.GetCommand(cmd)

	if !utils.IsEnableVyosCmd() {
		setZebraRoutes(cmd.Routes)
	} else {
		setRoutes(cmd.Routes)
	}
	return nil
}

func getCurrentStaticRoutes(tree *server.VyosConfigTree) (routes []routeInfo) {
	var infos []routeInfo
	rnode := tree.Get("protocols static route")
	if rnode == nil {
		return infos
	}
	for _, r := range rnode.Children() {
		nhop := r.Get("next-hop")
		if nhop != nil {
			for _, n := range nhop.Children() {
				dis := n.GetChildrenValue("distance")
				distance, _ := strconv.Atoi(dis)
				var info = routeInfo{Destination: r.Name(), Target: n.Name(), Distance: distance}
				infos = append(infos, info)
			}
		}

		bh := r.Get("blackhole")
		if bh != nil {
			dis := bh.GetChildrenValue("distance")
			distance, _ := strconv.Atoi(dis)
			var info = routeInfo{Destination: r.Name(), Target: "", Distance: distance}
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
		sameNexthop := false
		samePrefix := false
		for _, r := range infos {
			if r.Destination == o.Destination {
				samePrefix = true
			}
			if r.Destination == o.Destination && r.Target == o.Target {
				sameNexthop = true
			}
			if r.Destination == o.Destination && r.Target == o.Target && r.Distance == o.Distance {
				delete = false
				break
			}
		}
		if delete {
			log.Debugf("delete old route: %+v, sameNexthop: %+v, sameprefix: %+v", o, sameNexthop, samePrefix)
			if o.Target == "" {
				if sameNexthop {
					tree.Deletef("protocols static route %s blackhole distance %d ", o.Destination, o.Distance)
				} else if samePrefix {
					tree.Deletef("protocols static route %s blackhole", o.Destination)
				} else {
					tree.Deletef("protocols static route %s", o.Destination)
				}
			} else {
				if sameNexthop {
					tree.Deletef("protocols static route %s next-hop %s distance %d", o.Destination, o.Target, o.Distance)
				} else if samePrefix {
					tree.Deletef("protocols static route %s next-hop %s", o.Destination, o.Target)
				} else {
					tree.Deletef("protocols static route %s", o.Destination)
				}
			}
		}
	}

	tree.Apply(false)
}

func getLinuxRoutes() (ret int, output string, stderr string, err error) {
	// Note(WeiW): add "vtysh -c "show ip route " >/dev/null" to get correct return code
	bash := utils.Bash{
		Command: fmt.Sprintf("vtysh -c 'show ip route' | tail -n +4; vtysh -c 'show ip route' >/dev/null"),
	}
	return bash.RunWithReturn()
}

func getRoutes(ctx *server.CommandContext) interface{} {
	ret, o, _, err := getLinuxRoutes()
	utils.PanicOnError(err)
	if ret != 0 {
		utils.PanicOnError(errors.Errorf(("get route from zebra error")))
	}
	return GetRoutesRsp{RawRoutes: o}
}

func InitRoute() {
	if utils.IsVYOS() {
		return
	}

	if utils.IsEuler2203() {
		return
	}
	
	/* loongarch vpc will go here */
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo systemctl start zebra"),
	}
	bash.Run()
}

func RouteEntryPoint() {
	server.RegisterAsyncCommandHandler(SYNC_ROUTES, server.VyosLock(syncRoutes))
	server.RegisterAsyncCommandHandler(GET_ROUTES, server.VyosLock(getRoutes))
}
