package utils

import (
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
)

type CompareStringFunc func(string, string) bool

const (
	VYOS_1_1_7      = "1.1.7"
	VYOS_1_2        = "1.2"
	TIME_ZONE_FILE  = "/etc/timezone"
	LOCAL_TIME_FILE = "/etc/localtime"

	EULER_22_03 = "openEuler release 22.03 "
)

var (
	//fn, regFn CompareStringFunc
	StringCompareFn    = CompareString
	StringRegCompareFn = CompareRegString

	Cronjob_file_zsn         = "/usr/local/zstack/zsn-agent/bin/zsn-crontab.sh"

	Vyos_version_file = "/opt/vyatta/etc/version"
	Vyos_version      = VYOS_1_1_7

	Kernel_version = Kernel_3_13_11
	Kernel_3_13_11 = "3.13.11"
	Kernel_5_4_80  = "5.4.80"

	Euler_version_file = "/etc/system-release"
)


func GetZtackConfigPath() string {
	return filepath.Join(GetZvrRootPath(), ".zstack_config")
}

func GetCronjobFileSsh() string {
	return filepath.Join(GetZvrRootPath(), "ssh/sshd.sh")
}

func GetCronjobFileRsyslog() string {
	return filepath.Join(GetZvrRootPath(), "ssh/rsyslog.sh")
}

func GetCronjobFileZvrMonitor() string {
	return filepath.Join(GetZvrRootPath(), "ssh/zvr-monitor.sh")
}

func GetCronjobFileMonitor() string {
	return filepath.Join(GetZvrRootPath(), "ssh/file-monitor.sh")
}

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
	
	Vyos_version = "unknown"
	if ok, err := PathExists(Vyos_version_file); err == nil && ok {
		/* $ cat /opt/vyatta/etc/version
			Version:      VyOS 1.1.7
			Description:  VyOS 1.1.7 (helium)
			Copyright:    2016 VyOS maintainers and contributors
		*/
		log.Debugf("read /opt/vyatta/etc/version")
		if version, err := ReadLine(Vyos_version_file); err == nil {
			log.Debugf("version: " + version)
			if strings.Contains(version, VYOS_1_1_7) {
				Vyos_version = VYOS_1_1_7
			} else if strings.Contains(version, VYOS_1_2) {
				Vyos_version = VYOS_1_2
			}
		}
	} else if ok, err := PathExists(Euler_version_file); err == nil && ok {
		/* # cat /etc/system-release
			openEuler release 22.03 (LTS-SP3)
		*/
		log.Debugf("read /etc/system-release")
		if version, err := ReadLine(Euler_version_file); err == nil {
			log.Debugf("version: " + version)
			if strings.Contains(version, EULER_22_03) {
				Vyos_version = EULER_22_03
			} 
		}
	}
	log.Debugf("zstack vyos version %s", Vyos_version)
	
	b := &Bash{
		Command: "uname -r",
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
	var err error
	bash := Bash{
		Command: fmt.Sprintf("echo '%s:%s' | chpasswd", user, password),
		Sudo:    true,
	}

	if ret, _, _, err := bash.RunWithReturn(); ret == 0 && err == nil {
		return nil
	}
	return err
}

func SetTimeZone(timeZone string) error {
	if Vyos_version == EULER_22_03 {
		bash := Bash{
			Command: fmt.Sprintf("timedatectl set-timezone %s", timeZone),
			Sudo:    true,
		}
	
		return bash.Run()
	}

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

func ServiceOperation(name string, operation string) error {
	var command string
	if !HasSystemctl() {
		/* init service name is different from systemctl, remove last 'd' */
		/* rsyslog service name is rsyslog, not rsyslogd */
		if name != "rsyslog" {
			name = name[:len(name)-1]
		}
		command = fmt.Sprintf("/etc/init.d/%s %s", name, operation)
	} else {
		command = fmt.Sprintf("systemctl %s %s", operation, name)
	}

	bash := Bash{
		Command: command,
		Sudo:    true,
	}

	return bash.Run()
}

func HasSystemctl() bool {
	bash := Bash{
		Command: "which systemctl",
	}

	if ret, _, _, err := bash.RunWithReturn(); ret == 0 && err == nil {
		return true
	}

	return false
}