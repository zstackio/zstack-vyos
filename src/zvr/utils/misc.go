package utils
import (
        "regexp"
)

type CompareStringFunc func(string, string) bool

var (
        //fn, regFn CompareStringFunc
        StringCompareFn = CompareString
        StringRegCompareFn = CompareRegString

        Cronjob_file_ssh = "/home/vyos/zvr/ssh/sshd.sh"
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

