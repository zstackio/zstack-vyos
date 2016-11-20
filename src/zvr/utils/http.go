package utils

import (
	"net/http"
	"encoding/json"
	"github.com/pkg/errors"
	"fmt"
	"bytes"
	"io/ioutil"
	"github.com/Sirupsen/logrus"
)

var (
	HEADER_TRIGGER_URL = "TriggerURL"
)

func HttpPostWithoutHeaders(url string, obj interface{}) ([]byte, error) {
	return HttpPost(url, nil, obj)
}

func HttpPostForObject(url string, headers map[string]string, obj interface{}, retObj interface{}) error {
	b, err := HttpPost(url, headers, obj)
	if err != nil {
		return err
	}

	if retObj == nil {
		return nil
	}

	err = json.Unmarshal(b, retObj)
	if err != nil {
		return errors.Wrap(err, "failed to json unmarshal response body")
	}

	return nil
}

func HttpPostForObjectWithoutHeaders(url string, obj interface{}, retObj interface{}) error {
	return HttpPostForObject(url, nil, obj, retObj)
}

type HttpPostError struct {
	error
	statusCode int
}

func (e *HttpPostError) StatusCode() int {
	return e.statusCode
}

func HttpPost(url string, headers map[string]string, obj interface{}) ([]byte, error) {
	var b []byte
	var err error

	if (obj != nil) {
		b, err = json.Marshal(obj)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("unable to do HTTP post to %v", url))
		}
	} else {
		b = []byte("")
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("unable to do HTTP post to %v", url))
	}

	if (headers != nil) {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}

	c := &http.Client{}

	triggerUrl := req.Header.Get(HEADER_TRIGGER_URL)
	if triggerUrl != "" {
		logrus.Debugf("[HTTP POST][ASYNC REPLY TO %s] %s, body: %s", triggerUrl, url, string(b))
	} else {
		logrus.Debugf("[HTTP POST] %s, body: %s", url, string(b))
	}

	rsp, err := c.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("unable to do HTTP post to %v", url))
	}

	defer rsp.Body.Close()

	body, err := ioutil.ReadAll(rsp.Body)
	LogError(err)

	if rsp.StatusCode < 200 || rsp.StatusCode > 300 {
		return nil, &HttpPostError{
			errors.New(fmt.Sprintf("unable to post to the URL[%s], %s, %s", url, rsp.Status, string(body))),
			rsp.StatusCode,
		}
	}

	return body, nil
}
