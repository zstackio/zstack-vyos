package utils

import (
	"bytes"
	"text/template"
	"os/exec"
	"syscall"
	"errors"
	"fmt"
)

type Bash struct {
	Command string
	PipeFail bool
	Arguments map[string]string
}

func (b *Bash) build() {
	if (b.Command == "") {
		panic(errors.New("Command cannot be nil"))
	}

	if (b.Arguments != nil) {
		tmpl, err := template.New("script").Parse(b.Command)
		if err != nil {
			panic(err)
		}

		var buf bytes.Buffer
		err = tmpl.Execute(&buf, b.Arguments)
		if err != nil {
			panic(err)
		}

		b.Command = buf.String()
	}

	if b.PipeFail {
		b.Command = fmt.Sprintf("set -o pipefail; %s", b.Command)
	}
}

func (b *Bash) Run() error {
	b.build()
	ret, so, se := b.RunWithReturn()
	if ret != 0 {
		return fmt.Errorf("failed to exectue the command[%s]\nreturn code:%d\nstdout:%s\nstderr:%s\n",
			b.Command, ret, so, se)
	}

	return nil
}

func (b *Bash) RunWithReturn() (retCode int, stdout, stderr string) {
	b.build()

	var so, se bytes.Buffer
	cmd := exec.Command("bash", "-c", b.Command)
	cmd.Stdout = &so
	cmd.Stderr = &se

	var waitStatus syscall.WaitStatus
	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus = exitError.Sys().(syscall.WaitStatus)
			retCode = waitStatus.ExitStatus()
		} else {
			panic(errors.New("unable to get return code"))
		}
	} else {
		waitStatus = cmd.ProcessState.Sys().(syscall.WaitStatus)
		retCode = waitStatus.ExitStatus()
	}

	stdout = string(so.Bytes())
	stderr = string(se.Bytes())

	return
}

func NewBash() *Bash {
	return &Bash{}
}


