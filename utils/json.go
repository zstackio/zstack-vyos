package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
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
		return nil
	}

	return json.Unmarshal(f, v)
}

func JsonStoreConfig(filepath string, v interface{}) error {
	if filepath == "" {
		return errors.New("filepath can not be empty")
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	err = json.Indent(&out, data, "", "\t")
	if err != nil {
		return err
	}
	if ok, err := PathExists(filepath); err != nil || !ok {
		MkdirForFile(filepath, 0755)
	}

	return ioutil.WriteFile(filepath, out.Bytes(), 0664)
}