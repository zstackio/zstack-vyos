package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func JsonDecodeHttpRequest(req *http.Request, val interface{}) (err error) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return errors.Wrap(err, "unable to read the request, %s")
	}

	if err = json.Unmarshal(body, val); err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to parse string '%s' to JSON object", string(body)))
	}

	return nil
}

func JsonLoadConfig(filepath string, v interface{}) error {
	if filepath == "" {
		return errors.New("filepath can not be empty")
	}
	if ok, err := PathExists(filepath); err != nil || !ok {
		return nil
	}
	f, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}
	if len(f) == 0 {
		log.Debugf("file %s is empty", filepath)
		return nil
	}

	return json.Unmarshal(f, v)
}

func JsonStoreConfig(filepath string, v interface{}) error {
	var out bytes.Buffer
	if filepath == "" {
		return errors.New("filepath can not be empty")
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	err = json.Indent(&out, data, "", "\t")
	if err != nil {
		return err
	}
	if ok, err := PathExists(filepath); err != nil || !ok {
		MkdirForFile(filepath, 0755)
	}
	content := string(out.Bytes())
	content = strings.ReplaceAll(content, "\\u003c", "<")
	content = strings.ReplaceAll(content, "\\u003e", ">")

	return ioutil.WriteFile(filepath, []byte(content), 0664)
}
