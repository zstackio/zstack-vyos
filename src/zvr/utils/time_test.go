package utils

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLoopRunUntilSuccessOrTimeout(t *testing.T) {
	count := 0

	err := LoopRunUntilSuccessOrTimeout(func() bool {
		count++
		return count == 3
	}, time.Duration(1500)*time.Millisecond, time.Duration(500)*time.Millisecond)
	if !strings.Contains(err.Error(), "fn failed") {
		t.Fatal("fn should have been failed")
	}

	err = LoopRunUntilSuccessOrTimeout(func() bool {
		return false
	}, time.Duration(1500)*time.Millisecond, time.Duration(500)*time.Millisecond)
	Assert(err != nil, "")
	fmt.Printf("%v\n", err)
}
