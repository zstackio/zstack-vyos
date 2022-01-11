package plugin

import (
	"github.com/zstackio/zstack-vyos/utils"
	"time"
)

/*
the current health of whole system
*/
type HealthStatus struct {
	Healthy      bool   `json:"healthy"`
	HealthDetail string `json:"healthDetail"`
}

type healthCheckCallback interface {
	healthCheck() HealthStatus
}

var (
	healthStatus   = &HealthStatus{Healthy: true, HealthDetail: ""}
	checkCallbacks = make([]healthCheckCallback, 0)
)

func RegisterHealthCheckCallback(cb healthCheckCallback) {
	checkCallbacks = append(checkCallbacks, cb)
}

func (status *HealthStatus) healthCheck() {
	s := HealthStatus{Healthy: true, HealthDetail: ""}
	for _, cb := range checkCallbacks {
		if s = cb.healthCheck(); !s.Healthy {
			break
		}
	}
	*status = s
}

func init() {
	if utils.IsRuingUT() {
		return
	}

	go func() {
		for {
			healthStatus.healthCheck()
			time.Sleep(time.Duration(60 * time.Second))
		}
	}()
}
