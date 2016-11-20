package utils

import (
	"fmt"
	"strings"
	"strconv"
	"time"
)

func FindPIDByPS(cmdline...string) (int, error) {
	Assert(cmdline != nil, "cmdline must have one parameter at least")

	cmds := []string {"ps aux"}
	for _, c := range cmdline {
		cmds = append(cmds, fmt.Sprintf("grep '%s'", c))
	}
	cmds = append(cmds, "grep -v grep")
	cmds = append(cmds, "awk '{print $2}'")

	b := Bash{
		Command: strings.Join(cmds, " | "),
	}

	ret, o, _, err := b.RunWithReturn()
	if err != nil {
		return -2, err
	}

	o = strings.TrimSpace(o)
	if ret != 0 || o == "" {
		return -1, fmt.Errorf("cannot find any process having command line%v", cmdline)
	}

	return strconv.Atoi(o)
}

func KillProcess(pid int) error {
	return KillProcess1(pid, 15)
}

func KillProcess1(pid int, waitTime uint) error {
	b := Bash{
		Command: fmt.Sprintf("kill %v", pid),
	}
	b.Run()

	check := func() bool {
		b := Bash{
			Command: fmt.Sprintf("ps -p %v", pid),
		}

		ret, _, _, _ := b.RunWithReturn()
		return ret != 0
	}

	if check() {
		return nil
	}

	return LoopRunUntilSuccessOrTimeout(func() bool {
		b := Bash{
			Command: fmt.Sprintf("kill -9 %v", pid),
		}
		b.Run()

		return check()
	}, time.Duration(waitTime) * time.Second, time.Duration(500) * time.Millisecond)
}
