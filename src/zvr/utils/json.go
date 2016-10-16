package utils

import (
	"io/ioutil"
	"fmt"
	"encoding/json"
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
