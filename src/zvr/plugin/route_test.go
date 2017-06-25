package plugin

import (
	"testing"
	"zvr/server"
	"fmt"
)

var routeInfos = []routeInfo{
	routeInfo{
		Destination: "1.1.1.0/24",
		Target:      "172.20.1.1",
		Distance:    128,
	},

	routeInfo{
		Destination: "1.1.2.0/24",
		Target:      "172.20.1.1",
		Distance:    1,
	},

	routeInfo{
		Destination: "1.1.3.0/24",
		Distance:    128,
	},
}

func TestSyncRoutes(t *testing.T) {
	server.UNIT_TEST = true
	runVyosScript = func(script string, args map[string]string) {
		fmt.Println(script)
	}

	server.ConfigurationSourceFunc = func() string {
		return `
interfaces {
    ethernet eth0 {
        address 172.20.14.114/16
        description main
        duplex auto
        hw-id fa:62:6b:d9:10:00
        smp_affinity auto
        speed auto
    }
    loopback lo {
    }
}`
	}

	setRoutes(routeInfos)
}
