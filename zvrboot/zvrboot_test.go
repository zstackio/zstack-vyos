package main

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"testing"
	"zvr/utils"
)

func setUp() {
	utils.InitLog(utils.VYOS_UT_LOG_FOLDER + "zvrboot.log", false)
	waitIptablesServiceOnline()
	content := ``
	if err := json.Unmarshal([]byte(content), &bootstrapInfo); err != nil {
		panic(errors.Wrap(err, fmt.Sprintf("unable to JSON parse:\n %s", string(content))))
	}
	utils.InitVyosVersion()
	configureVyos()
}

func TestZvrboot(t *testing.T) {
	//setUp()
	/* add expectation check */
}
