package utils

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"runtime"
	"strings"

	log "github.com/Sirupsen/logrus"
)

type CompareStringFunc func(string, string) bool

const (
	VYOS_1_1_7         = "1.1.7"
	VYOS_1_2           = "1.2"
	TIME_ZONE_FILE     = "/etc/timezone"
	LOCAL_TIME_FILE    = "/etc/localtime"
	ZSTACK_CONFIG_PATH = "/home/vyos/zvr/.zstack_config"
)

var (
	//fn, regFn CompareStringFunc
	StringCompareFn    = CompareString
	StringRegCompareFn = CompareRegString

	Cronjob_file_ssh         = "/home/vyos/zvr/ssh/sshd.sh"
	Cronjob_file_rsyslog     = "/home/vyos/zvr/ssh/rsyslog.sh"
	Cronjob_file_zsn         = "/usr/local/zstack/zsn-agent/bin/zsn-crontab.sh"
	Cronjob_file_zvrMonitor  = "/home/vyos/zvr/ssh/zvr-monitor.sh"
	Cronjob_file_fileMonitor = "/home/vyos/zvr/ssh/file-monitor.sh"

	Vyos_version_file = "/opt/vyatta/etc/version"
	Vyos_version      = VYOS_1_1_7

	Kernel_version = Kernel_3_13_11
	Kernel_3_13_11 = "3.13.11"
	Kernel_5_4_80  = "5.4.80"
)

func CompareString(src, target string) bool {
	if src == target {
		return true
	} else {
		return false
	}
}

func CompareRegString(reg, src string) bool {
	if matched, err := regexp.MatchString(reg, src); err == nil && matched {
		return true
	} else {
		return false
	}
}

func InitVyosVersion() {
	content, err := ioutil.ReadFile(Vyos_version_file)
	if err == nil && len(content) != 0 {
		temp := strings.TrimSpace(string(content))
		if strings.Contains(temp, VYOS_1_1_7) {
			Vyos_version = VYOS_1_1_7
		} else if strings.Contains(temp, VYOS_1_2) {
			Vyos_version = VYOS_1_2
		}
	}
	log.Debugf("zstack vyos version %s", Vyos_version)

	b := &Bash{
		Command: fmt.Sprintf("uname -r"),
	}
	ret, out, _, _ := b.RunWithReturn()
	if ret == 0 {
		unameR := strings.Split(out, "-")
		Kernel_version = unameR[0]
		log.Debugf("zstack kernel version %s", Kernel_version)
	}
}

func GetCpuNum() int {
	return runtime.NumCPU()
}

func Arping(nicname string, ip string, gateway string) {
	b := Bash{
		Command: fmt.Sprintf("arping -q -A -w 2 -c 1 -I %s %s > /dev/null", nicname, ip),
		Sudo:    true,
	}
	b.Run()
}

func SetUserPasswd(user string, password string) error {
	bash := Bash{
		Command: fmt.Sprintf("echo '%s:%s' | chpasswd", user, password),
		Sudo:    true,
	}

	return bash.Run()
}

func SetTimeZone(timeZone string) error {
	Assertf(timeZone != "", "time zone can not be empty")

	bash := Bash{
		Command: fmt.Sprintf("echo '%s' > %s; cp /usr/share/zoneinfo/%s %s", timeZone, TIME_ZONE_FILE, timeZone, LOCAL_TIME_FILE),
		Sudo:    true,
	}

	return bash.Run()
}

func SetNicOption(devName string) {
	Assertf(devName != "", "device name can not be empty")
	bash := Bash{
		Command: fmt.Sprintf("ethtool -s %s speed 1000 duplex full", devName),
		Sudo:    true,
	}

	bash.Run()
}
