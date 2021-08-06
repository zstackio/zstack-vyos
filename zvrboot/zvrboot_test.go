package main

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/zstackio/zstack-vyos/utils/test"
	"testing"
	"github.com/zstackio/zstack-vyos/utils"
)

func setUp() {
	utils.InitLog(test.VYOS_UT_LOG_FOLDER + "zvrboot.log", false)
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
