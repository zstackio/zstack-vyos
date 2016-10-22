package main

import (
	"fmt"
	"flag"
	"os"
	"zvr/server"
)

func abortOnWrongOption(msg string) {
	fmt.Println(msg)
	flag.Usage()
	os.Exit(1)
}

func parseCommandOptions(defaultPort uint) server.Options  {
	options := server.Options{}
	flag.StringVar(&options.Ip, "ip", "", "The IP address the server listens on")
	flag.UintVar(&options.Port, "port", defaultPort, "The port the server listens on")
	flag.UintVar(&options.ReadTimeout, "readtimeout", 10, "The socket read timeout")
	flag.UintVar(&options.WriteTimeout, "writetimeout", 10, "The socket write timeout")
	flag.StringVar(&options.LogFile, "logfile", "zvr.log", "The log file path")

	flag.Parse()

	if options.Ip == "" {
		abortOnWrongOption("error: the options 'ip' is required")
	}

	return options
}
