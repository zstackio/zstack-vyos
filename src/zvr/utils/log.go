package utils

import (
	"encoding/json"
	"fmt"
	"strings"
	"os"
	"io"
	log "github.com/Sirupsen/logrus"
)

type logFormatter struct {
}

const timeFormat  = "2006-01-02 15:04:05" //"Jan 2, 2006 at 3:04pm (MST)"

func (f *logFormatter) Format(entry *log.Entry) ([]byte, error) {
	//timestampFormat := log.DefaultTimestampFormat

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

		msg = fmt.Sprintf("%v %v %v %v", entry.Time.Format(timeFormat),
			strings.ToUpper(entry.Level.String()), entry.Message, string(jsondata))
	} else {
		msg = fmt.Sprintf("%v %v %v", entry.Time.Format(timeFormat),
			strings.ToUpper(entry.Level.String()), entry.Message)
	}

	return append([]byte(msg), '\n'), nil
}

func InitLog(logpath string, stdout bool) {
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&logFormatter{})
	logFile, err := CreateFileIfNotExists(logpath, os.O_WRONLY | os.O_APPEND, 0666); PanicOnError(err)
	if stdout {
		multi := io.MultiWriter(logFile, os.Stdout)
		log.SetOutput(multi)
	} else {
		log.SetOutput(logFile)
	}
}
