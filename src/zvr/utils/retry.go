package utils

import (
	"time"
	log "github.com/Sirupsen/logrus"
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
		log.Warnf("failed to execute a function, sleep %d seconds and will retry %s times, %v",
			retryTimes, interval, err)
		time.Sleep(time.Duration(interval) * time.Second)
		retryTimes --
	}
}
