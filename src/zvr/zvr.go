package main

import (
	"zvr/server"
	"zvr/plugin"
	"fmt"
	"flag"
	"os"
	"zvr/utils"
	"io"
	"encoding/json"
	"strings"
	log "github.com/Sirupsen/logrus"
)

func loadPlugins()  {
	plugin.DhcpEntryPoint()
	plugin.MiscEntryPoint()
}

func abortOnWrongOption(msg string) {
	fmt.Println(msg)
	flag.Usage()
	os.Exit(1)
}

var options server.Options

func parseCommandOptions()  {
	options = server.Options{}
	flag.StringVar(&options.Ip, "ip", "", "The IP address the server listens on")
	flag.UintVar(&options.Port, "port", 7272, "The port the server listens on")
	flag.UintVar(&options.ReadTimeout, "readtimeout", 10, "The socket read timeout")
	flag.UintVar(&options.WriteTimeout, "writetimeout", 10, "The socket write timeout")
	flag.StringVar(&options.LogFile, "logfile", "zvr.log", "The log file path")

	flag.Parse()

	if options.Ip == "" {
		abortOnWrongOption("error: the options 'ip' is required")
	}

	server.SetOptions(options)
}

type logFormatter struct {
}

func (f *logFormatter) Format(entry *log.Entry) ([]byte, error) {
	timestampFormat := log.DefaultTimestampFormat

	var msg string
	if len(entry.Data) > 0 {
		data := make(log.Fields, len(entry.Data))
		for k, v := range entry.Data {
			switch v := v.(type) {
			case error:
				data[k] = v.Error()
			default:
				data[k] = v
			}
		}

		jsondata, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal fields to JSON, %v", err)
		}

		msg = fmt.Sprintf("%v %v %v %v", entry.Time.Format(timestampFormat),
			strings.ToUpper(entry.Level.String()), entry.Message, string(jsondata))
	} else {
		msg = fmt.Sprintf("%v %v %v", entry.Time.Format(timestampFormat),
			strings.ToUpper(entry.Level.String()), entry.Message)
	}

	return append([]byte(msg), '\n'), nil
}

func initLog() {
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&logFormatter{})
	logFile, err := utils.CreateFileIfNotExists(options.LogFile, os.O_WRONLY|os.O_APPEND, 0666); utils.PanicOnError(err)
	multi := io.MultiWriter(logFile, os.Stdout)
	log.SetOutput(multi)
}

func main()  {
	parseCommandOptions()
	initLog()
	loadPlugins()

	server.Start()
}