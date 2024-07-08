package utils

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

func setTestBashTestEnv() {
	InitLog(GetVyosUtLogDir()+"bash_test.log", false)
}

func TestBash(t *testing.T) {
	setTestBashTestEnv()
	b := NewBash()
	b.Command = "ls"
	b.Run()

	ret, so, se, err := b.RunWithReturn()
	fmt.Printf("%v, %v, %v", ret, so, se)

	b = NewBash()
	b.Command = "ls a"
	err = b.Run()
	if err == nil {
		t.Fatal("error cannot be null")
	}

	ret, so, se, err = b.RunWithReturn()
	if ret == 0 {
		t.Fatal("the command should fail")
	}
	fmt.Printf("%v, %v, %v", ret, so, se)

	b = NewBash()
	b.Command = "ls {{.File}}"
	b.Arguments = map[string]string{
		"File": "b",
	}

	ret, so, se, err = b.RunWithReturn()
	if ret == 0 {
		t.Fatal("the command should fail")
	}
	fmt.Printf("%v, %v, %v", ret, so, se)
}

func TestSudo(t *testing.T) {
	b := NewBash()
	f := "/etc/gotest.log"
	b.Command = "echo hi; echo again; echo hello > {{.File}}"
	b.Sudo = true
	b.Arguments = map[string]string{
		"File": f,
	}
	_, o, _, err := b.RunWithReturn()
	if err != nil {
		t.Fatal("command failed", err)
	}

	if !strings.Contains(o, "hi") || !strings.Contains(o, "again") || strings.Contains(o, "hello") {
		t.Fatal("unexpected output:", o)
	}

	b2 := &Bash{Command: "rm -f " + f, Sudo: true}
	defer b2.Run()

	buf, err := ioutil.ReadFile(f)
	if err != nil {
		t.Fatal("file not exists", err)
	}

	if !strings.Contains(string(buf), "hello") {
		t.Fatal("unexpected content:", string(buf))
	}
}

func TestSudo1(t *testing.T) {
	b := Bash{
		Command: "touch /root/gotest.log; echo hello > /root/gotest.log; rm /root/gotest.log",
		Sudo:    false,
	}

	ret, _, _, err := b.RunWithReturn()
	if err == nil || ret == 0 {
		t.Fatal("command failed", err)
	}

	b.Sudo = true
	ret, _, _, err = b.RunWithReturn()
	if err != nil || ret != 0 {
		t.Fatal("command failed", err)
	}
}
