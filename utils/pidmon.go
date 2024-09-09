package utils

import (
	"fmt"
	"time"
)

// pidmon - a simple pid monitor.
type PidMon struct {
	pid          int
	onPidMissing func() int
	ok           bool
	interval     time.Duration
}

func NewPidMon(pid int, onMissing func() int) *PidMon {
	return &PidMon{
		pid:          pid,
		onPidMissing: onMissing,
		ok:           true,
		interval:     150 * time.Millisecond,
	}
}

func (pm *PidMon) Start() error {
	if ProcessExists(pm.pid) != nil {
		return fmt.Errorf("pid[%d] not exists", pm.pid)
	}

	go func() {
		for pm.ok {
			time.Sleep(pm.interval)
			/* maybe pid monitor is stopped after sleep */
			if !pm.ok {
				return
			}

			if ProcessExists(pm.pid) == nil {
				continue
			}

			if n := pm.onPidMissing(); n > 0 {
				pm.pid = n
			}
		}
	}()

	return nil
}

func (pm *PidMon) Stop() {
	pm.ok = false
}

func (pm *PidMon) Destroy() {
	pm.ok = false

	if ProcessExists(pm.pid) == nil {
		KillProcess(pm.pid)
	}
}
