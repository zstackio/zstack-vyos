package zvr

import (
	"strings"
	"zvr/utils"
	"fmt"
	"strconv"
)

func FindNicNameByMac(mac string) (string, bool) {
	parser := NewParserFromShowConfiguration()

	config, ok := parser.GetConfig("interfaces ethernet")
	if !ok {
		return "", false
	}

	for _, eth := range config.Keys() {
		c, _ := config.GetConfig(eth)
		hw, ok := c.GetValue("hw-id")
		if !ok {
			continue
		}

		if strings.ToLower(mac) == hw {
			return eth, true
		}
	}

	return "", false
}

func RunVyosScript(command string, args map[string]string) {
	template := `SET=${vyatta_sbindir}/my_set
DELETE=${vyatta_sbindir}/my_delete
COPY=${vyatta_sbindir}/my_copy
MOVE=${vyatta_sbindir}/my_move
RENAME=${vyatta_sbindir}/my_rename
ACTIVATE=${vyatta_sbindir}/my_activate
DEACTIVATE=${vyatta_sbindir}/my_activate
COMMENT=${vyatta_sbindir}/my_comment
COMMIT=${vyatta_sbindir}/my_commit
DISCARD=${vyatta_sbindir}/my_discard
SAVE=${vyatta_sbindir}/vyatta-save-config.pl
API=/bin/cli-shell-api

session_env=$($API getSessionEnv $PPID)
echo $session_env
eval $session_env
$API setupSession

set -e
%s
$COMMIT
set +e

function atexit() {
    $API teardownSession
}

trap atexit EXIT SIGHUP SIGINT SIGTERM
`
	bash := &utils.Bash{
		Command: fmt.Sprintf(template, command),
		Arguments: args,
	}
	bash.Run()
	bash.PanicIfError()
}

func NetmaskToCIDR(netmask string) (int, error) {
	countBit := func(num uint) int {
		count := uint(0)
		var i uint
		for i = 31; i>0; i-- {
			count += ((num << i) >> uint(31)) & uint(1)
		}

		return int(count)
	}

	cidr := 0
	for _, o := range strings.Split(netmask, ".") {
		num, err := strconv.ParseUint(o, 10, 32)
		if err != nil {
			return -1, err
		}
		cidr += countBit(uint(num))
	}

	return cidr, nil
}
