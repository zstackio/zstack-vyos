package utils

import (
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

        b := Bash{
                Command: "! grep -w 'fs' /tmp/sysctl.conf | grep nr_open  && sed -i 's/fs.nr_open=[0-9]*/fs.nr_open=20971520/' /tmp/sysctl.conf   || echo 'fs.nr_open=20971520'  >> /etc/sysctl.conf;" +
                        "! grep -w 'fs' /tmp/sysctl.conf | grep file-max && sed -i 's/fs.file-max=[0-9]*/fs.file-max=26268608/' /tmp/sysctl.conf || echo 'fs.file-max=26268608' >> /etc/sysctl.conf",
        }
        b.Run()
        b.PanicIfError()
}

func GetCpuNum() int  {
        return runtime.NumCPU()
}