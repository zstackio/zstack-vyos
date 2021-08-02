package utils

import (
	"time"
	"fmt"
	"github.com/pkg/errors"
)

func LoopRunUntilSuccessOrTimeout(fn func() bool, timeout, interval time.Duration) error {
	expiredTime := time.Now().Add(timeout)
	tk := time.NewTicker(interval)
	defer tk.Stop()

	for {
		if fn() {
			return nil
		}

		now := <- tk.C
		if now.After(expiredTime) {
			return errors.New(fmt.Sprintf("timeout after %v", timeout))
		}
	}
}
