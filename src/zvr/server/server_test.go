package server

import (
	"testing"
	"zvr/utils"
	"fmt"
	"github.com/pkg/errors"
	"net/http"
	"time"
)

func startMockServer()  {
	commandOptions.Ip = "127.0.0.1"
	commandOptions.Port = 8989
	go func() {
		startServer()
	}()
	time.Sleep(time.Duration(2) * time.Second)
}

type syncCmd struct {
	Greeting string
}

func makeURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:8989%s", path)
}

func TestSyncCommand(t *testing.T)  {
	startMockServer()

	testCmd := syncCmd{
		Greeting: "hello",
	}

	success := false
	path := "/testsync"
	RegisterSyncCommandHandler(path, func (ctx *CommandContext) interface{} {
		cmd := &syncCmd{}
		ctx.GetCommand(cmd)
		success = cmd.Greeting == testCmd.Greeting
		fmt.Println(cmd.Greeting)
		return nil
	})

	utils.HttpPostWithoutHeaders(makeURL(path), &testCmd)
	utils.Assert(success, "not working")
}

func TestCommandHandlerPanic(t *testing.T)  {
	startMockServer()

	path := "/testpanic1"
	RegisterSyncCommandHandler(path, func (ctx *CommandContext) interface{} {
		panic(errors.New("on purpose"))
	})
	utils.HttpPostWithoutHeaders(makeURL(path), nil)

	path = "/testpanic2"
	s := false
	RegisterSyncCommandHandler(path, func (ctx *CommandContext) interface{} {
		s = true
		return nil
	})
	utils.HttpPostWithoutHeaders(makeURL(path), nil)
	utils.Assert(s, "not working")
}


type asyncCmd struct {
	Say string
}

type asyncReply struct {
	Greeting string
}

func TestAsyncCommand(t *testing.T) {
	startMockServer()

	taskUuid := "abcd"
	callbackPath := "/callback"
	callbackURL := fmt.Sprintf("http://127.0.0.1:9090%s", callbackPath)
	s1 := false
	s2 := false
	http.HandleFunc(callbackPath, func(w http.ResponseWriter, req *http.Request) {
		reply := &asyncReply{}
		utils.JsonDecodeHttpRequest(req, reply)
		s1 = reply.Greeting == "hello"
		s2 = req.Header.Get(TASK_UUID) == taskUuid
	})

	go func() {
		http.ListenAndServe("127.0.0.1:9090", nil)
	}()

	time.Sleep(time.Duration(2) * time.Second)

	s3 := false
	path := "/testasync"
	RegisterAsyncCommandHandler(path, func (ctx *CommandContext) interface{} {
		cmd := &asyncCmd{}
		ctx.GetCommand(cmd)
		s3 = cmd.Say == "hi"

		reply := &asyncReply{}
		reply.Greeting = "hello"
		return reply
	})

	utils.HttpPost(makeURL(path), map[string]string{
		CALLBACK_URL: callbackURL,
		TASK_UUID: taskUuid,
	}, &asyncCmd{ Say: "hi"})

	time.Sleep(time.Duration(2) * time.Second)
	utils.Assert(s1, "s1")
	utils.Assert(s2, "s2")
	utils.Assert(s3, "s3")
}

func TestAsyncCommandNoTaskUUID(t *testing.T) {
	startMockServer()

	path := "/testasync"
	RegisterAsyncCommandHandler(path, func (ctx *CommandContext) interface{} {
		// pass
		return nil
	})

	// no task UUID
	_, err := utils.HttpPost(makeURL(path), map[string]string{
		CALLBACK_URL: "abcde",
	}, &asyncCmd{ Say: "hi"})

	time.Sleep(time.Duration(2) * time.Second)
	utils.Assert(err != nil, err.Error())
	fmt.Println(err.Error())
}

func TestAsyncCommandNoCallbackURL(t *testing.T) {
	startMockServer()

	path := "/testasync"
	RegisterAsyncCommandHandler(path, func (ctx *CommandContext) interface{} {
		// pass
		return nil
	})

	// no callback URL
	_, err := utils.HttpPost(makeURL(path), map[string]string{
		TASK_UUID: "abc",
	}, &asyncCmd{ Say: "hi"})

	time.Sleep(time.Duration(2) * time.Second)
	utils.Assert(err != nil, err.Error())
	fmt.Println(err.Error())
}