package utils

import (
        "fmt"
        log "github.com/Sirupsen/logrus"
        "io/ioutil"
        "regexp"
        "runtime"
        "strings"
)

type CompareStringFunc func(string, string) bool

const (
        VYOS_1_1_7 = "1.1.7"
        VYOS_1_2   = "1.2"
)

var (
        //fn, regFn CompareStringFunc
        StringCompareFn = CompareString
        StringRegCompareFn = CompareRegString

        Cronjob_file_ssh = "/home/vyos/zvr/ssh/sshd.sh"
        Cronjob_file_zsn = "/usr/local/zstack/zsn-agent/bin/zsn-crontab.sh"

        Vyos_version_file = "/opt/vyatta/etc/version"
        Vyos_version = VYOS_1_1_7

        Kernel_version = Kernel_3_13_11
        Kernel_3_13_11 = "3.13.11"
        Kernel_5_4_80  = "5.4.80"
)

func CompareString(src, target string)  bool {
        if src == target {
                return true
        } else {
                return false
        }
}

func CompareRegString(reg, src string)  bool {
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

func GetCpuNum() int  {
        return runtime.NumCPU()
}