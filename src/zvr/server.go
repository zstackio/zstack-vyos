package zvr

import (
	"net/http"
	"fmt"
	"zvr/utils"
	"flag"
	"os"
	"time"
	"encoding/json"
)

type commandHandlerWrap struct {
	path string
	handler http.HandlerFunc
}

type options struct {
	ip string
	port uint
	readTimeout uint
	writeTimeout uint
}

type ReplyHeader struct {
	Success bool `json:"success"`
	Error string `json:"error"`
}

type CommandContext struct {
}

type CommandHandler interface {
	handleCommand(ctx *CommandContext) interface{}
}

type HttpInterceptor func(http.HandlerFunc) http.HandlerFunc

var (
	commandHandlers map[string]commandHandlerWrap = make(map[string]commandHandlerWrap)
	commandOptions = &options{}
	interceptors map[string][]HttpInterceptor = make(map[string][]HttpInterceptor, 0)
)

func RegisterHttpInterceptor(path string, ic HttpInterceptor)  {
	if ics, ok := interceptors[path]; !ok {
		ics := make([]HttpInterceptor, 0)
		append(ics, ic)
		interceptors[path] = ics
	} else {
		append(ics, ic)
	}
}

func RegisterCommandHandler(path string, chandler CommandHandler) {
	utils.Assert(path != nil, "path cannot be nil")
	utils.Assert(chandler != nil, "chandler cannot be nil")

	if _, ok := commandHandlers[path]; ok {
		panic(fmt.Errorf("duplicate handler for the path[%v]", path))
	}

	w := &commandHandlerWrap{
		path: path,
	}

	inner := func(w http.ResponseWriter, req *http.Request) {
		ctx := &CommandContext{}
		chandler.handleCommand(ctx)
	}

	for _, ics := range interceptors {
		for _, ic := range ics {
			inner = ic(inner)
		}
	}

	w.handler = func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				reply := ReplyHeader{
					Success: false,
					Error: fmt.Sprintf("%v", err),
				}

				body, err := json.Marshal(reply)
				if err != nil {
					//TODO: logging error
					w.WriteHeader(http.StatusInternalServerError)
					utils.LogError(fmt.Fprintf(w, fmt.Sprintf("%s", err)))
					return
				}

				w.WriteHeader(http.StatusOK)
				utils.LogError(fmt.Fprint(w, string(body)))
			}
		}()

		inner(w, req)
	}

	commandHandlers[path] = w
}

func abortOnWrongOption(msg string) {
	fmt.Println(msg)
	flag.Usage()
	os.Exit(1)
}

func parseCommandOptions()  {
	flag.StringVar(&commandOptions.ip, "ip", "", "The IP address the server listens on")
	flag.UintVar(&commandOptions.port, "port", 7272, "The port the server listens on")
	flag.UintVar(&commandOptions.readTimeout, "readtimeout", 10*time.Second, "The socket read timeout")
	flag.UintVar(&commandOptions.writeTimeout, "readtimeout", 10*time.Second, "The socket write timeout")

	flag.Parse()

	if commandOptions.ip == "" {
		abortOnWrongOption("error: the options 'ip' is required")
	}
}

func Start()  {
	parseCommandOptions()
	startServer()
}

func dispatch(w http.ResponseWriter, req *http.Request) {
}

func startServer() {
	server := &http.Server{
		Addr: fmt.Sprintf("%v:%v", commandOptions.ip, commandOptions.port),
		ReadTimeout: commandOptions.readTimeout,
		WriteTimeout: commandOptions.writeTimeout,
		Handler: dispatch,
	}

	server.ListenAndServe()
}
