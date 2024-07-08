package utils

import (
	"os"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

var handlers = make([]func(error), 0)

func writeFile(fpath, content string) error {
	defer os.Remove(fpath) // It's necessary.

	fh, err := os.Create(fpath)
	if err != nil {
		return err
	}

	if _, err = fh.WriteString(content); err != nil {
		fh.Close()
		return err
	}

	return fh.Close()
}

func checkIoError(fpath string) error {
	err := writeFile(fpath, time.Now().Format(time.RFC3339))
	if err == nil {
		return nil
	}

	// Only treat ENOSPC and EROFS as error
	patherr, ok := err.(*os.PathError)
	if ok && (patherr.Err == syscall.ENOSPC || patherr.Err == syscall.EROFS) {
		return err
	} else {
		log.Debugf("disk error: %v", err)
	}

	return nil
}

func diskmon(fpath string, onFailure func(error), interval time.Duration) {
	log.Debugf("start disk monitor: %s", fpath)
	for {
		if err := checkIoError(fpath); err != nil {
			log.Debugf("disk error: %v", err)
			for _, f := range handlers {
				f(err)
			}
			onFailure(err)
		}

		log.Debugf("disk no error")
		time.Sleep(interval)
	}
}

func RegisterDiskFullHandler(f func(error)) {
	handlers = append(handlers, f)
}

var once sync.Once

func StartDiskMon(fpath string, onFailure func(error), interval time.Duration) {
	once.Do(func() {
		go diskmon(fpath, onFailure, interval)
	})
}
