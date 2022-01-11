package utils

import (
	log "github.com/Sirupsen/logrus"
	"reflect"
	"runtime"
	"time"
)

func Retry(fn func() error, retryTimes uint, interval uint) error {
	for {
		err := fn()
		if err == nil {
			return nil
		}

		if retryTimes == 0 {
			return err
		}

		//TODO: add line number
		log.Warnf("failed to execute a function %v, sleep %d seconds and will retry %v times, %v",
			runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name(), interval, retryTimes, err)
		time.Sleep(time.Duration(interval) * time.Second)
		retryTimes--
	}
}
