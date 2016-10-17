package utils

import (
	"testing"
	"fmt"
)

func TestBash(t *testing.T)  {
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
	b.Arguments = map[string]string {
		"File": "b",
	}

	ret, so, se, err = b.RunWithReturn()
	if ret == 0 {
		t.Fatal("the command should fail")
	}
	fmt.Printf("%v, %v, %v", ret, so, se)
}
