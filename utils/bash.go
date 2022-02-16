package utils

import (
	"bytes"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"io/ioutil"
	"os/exec"
	"syscall"
	"text/template"
	"time"

	//"os"
	"os"
)

type Bash struct {
	Command   string
	PipeFail  bool
	Arguments map[string]string
	NoLog     bool
	Timeout   int
	Sudo      bool

	retCode int
	stdout  string
	stderr  string
	err     error
}

func (b *Bash) build() error {
	Assert(b.Command != "", "Command cannot be emptry string")

	if b.Arguments != nil {
		tmpl, err := template.New("script").Parse(b.Command)
		if err != nil {
			return err
		}

		var buf bytes.Buffer
		err = tmpl.Execute(&buf, b.Arguments)
		if err != nil {
			return err
		}

		b.Command = buf.String()
	}

	if b.PipeFail {
		b.Command = fmt.Sprintf("set -o pipefail; %s", b.Command)
	}

	if b.Timeout == 0 {
		b.Timeout = 300
	}

	return nil
}

func (b *Bash) Run() error {
	ret, so, se, err := b.RunWithReturn()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to execute the command[%s] because of an internal errro", b.Command))
	}

	if ret != 0 {
		return errors.New(fmt.Sprintf("failed to exectue the command[%s]\nreturn code:%d\nstdout:%s\nstderr:%s\n",
			b.Command, ret, so, se))
	}

	return nil
}

func (b *Bash) RunWithReturn() (retCode int, stdout, stderr string, err error) {
	if err = b.build(); err != nil {
		b.err = err
		return -1, "", "", err
	}

	if !b.NoLog {
		logrus.Debugf("shell start: %s", b.Command)
	}

	var so, se bytes.Buffer
	var cmd *exec.Cmd
	tmpfile, err := ioutil.TempFile("/home/vyos", "zvrcommand")
	PanicOnError(err)
	defer os.Remove(tmpfile.Name())

	cmdstr := b.Command

	if len(b.Command) > 1024*4 {
		func() {
			content := []byte(b.Command)
			err = tmpfile.Chmod(0775)
			PanicOnError(err)
			_, err = tmpfile.Write(content)
			PanicOnError(err)
			err = tmpfile.Close()
			PanicOnError(err)
			cmd = exec.Command("bash", "-c", tmpfile.Name())
			cmdstr = tmpfile.Name()
		}()
	}

	if b.Sudo {
		cmd = exec.Command("sudo", "bash", "-c", cmdstr)
	} else {
		cmd = exec.Command("bash", "-c", cmdstr)
	}

	cmd.Stdout = &so
	cmd.Stderr = &se
	if err = cmd.Start(); err != nil {
		return
	}

	done := make(chan error)
	go func() { done <- cmd.Wait() }()

	after := time.After(time.Duration(b.Timeout) * time.Second)
	select {
	case <-after:
		cmd.Process.Signal(syscall.SIGTERM)
		err = fmt.Errorf("bash command %s timeout after %d sec", b.Command, b.Timeout)
		retCode = -1
	case err = <-done:
		var waitStatus syscall.WaitStatus
		if err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				waitStatus = exitError.Sys().(syscall.WaitStatus)
				retCode = waitStatus.ExitStatus()
			} else {
				panic(errors.Errorf("unable to get return code, %s", err))
			}
		} else {
			waitStatus = cmd.ProcessState.Sys().(syscall.WaitStatus)
			retCode = waitStatus.ExitStatus()
		}
	}

	stdout = string(so.Bytes())
	stderr = string(se.Bytes())

	b.retCode = retCode
	b.stdout = stdout
	b.stderr = stderr

	if !b.NoLog {
		logrus.WithFields(logrus.Fields{
			"return code": fmt.Sprintf("%v", retCode),
			"stdout":      stdout,
			"stderr":      stderr,
			"err":         fmt.Sprintf("%v", err),
		}).Debugf("shell done: %s", b.Command)
	}

	return
}

func (bash *Bash) PanicIfError() {
	if bash.err != nil {
		panic(errors.New(fmt.Sprintf("shell failure[command: %v], internal error: %v",
			bash.Command, bash.err)))
	}

	if bash.retCode != 0 {
		panic(errors.New(fmt.Sprintf("shell failure[command: %v, return code: %v, stdout: %v, stderr: %v",
			bash.Command, bash.retCode, bash.stdout, bash.stderr)))
	}
}

func NewBash() *Bash {
	return &Bash{}
}
