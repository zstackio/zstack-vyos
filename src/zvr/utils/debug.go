package utils

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
)

func Assert(expression bool, msg string)  {
	if !expression {
		panic(errors.New(msg))
	}
}

func LogError(args...interface{})  {
	for _, arg := range args {
		if e, ok := arg.(error); ok {
			err := errors.Wrap(e, "UNHANDLED ERROR, PLEASE REPORT A BUG TO US")
			log.Warn(fmt.Sprintf("%+v\n", err))
		}
	}
}
