package utils

import (
	"testing"
	"fmt"
)

func returnError() (error, bool) {
	err := fmt.Errorf("this is an error")
	return err, true
}

func TestLogError(t *testing.T) {
	LogError(returnError())
	LogError(nil)
}
