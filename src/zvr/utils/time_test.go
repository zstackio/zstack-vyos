package utils

import (
	"testing"
	"time"
	"fmt"
)

func TestLoopRunUntilSuccessOrTimeout(t *testing.T) {
	count := 0

	err := LoopRunUntilSuccessOrTimeout(func() bool {
		count ++
		return count == 3
	}, time.Duration(1500) * time.Millisecond, time.Duration(500) * time.Millisecond)
	PanicOnError(err)

	err = LoopRunUntilSuccessOrTimeout(func() bool {
		return false
	}, time.Duration(1500) * time.Millisecond, time.Duration(500) * time.Millisecond)
	Assert(err != nil, "")
	fmt.Printf("%v\n", err)
}
