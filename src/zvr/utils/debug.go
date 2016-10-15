package utils

import "fmt"

func Assert(expression bool, msg string)  {
	if !expression {
		panic(fmt.Errorf(msg))
	}
}

func LogError(args...interface{})  {
	for _, arg := range args {
		if arg.(error) {
			//TODO: logging error here
		}
	}
}
