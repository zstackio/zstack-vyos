package plugin

import (
	"fmt"
	"github.com/zstackio/zstack-vyos/utils"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
)

const (
	CONNTRACK_BUCKETS         = 2842624
	CONNTRACK_BUCKETS_PATH    = "/sys/module/nf_conntrack/parameters/hashsize"
	CONNTRACK_BUCKETS_PATH_48 = "/proc/sys/net/netfilter/nf_conntrack_buckets"
	CONNTRACK_MAX             = 22740992
	CONNTRACK_MAX_PATH        = "/proc/sys/net/netfilter/nf_conntrack_max"
)

func getKernelVersion() float64 {
	b := &utils.Bash{
		Command: fmt.Sprintf("uname -r"),
	}
	_, out, _, err := b.RunWithReturn()
	utils.PanicOnError(err)
	unameR := strings.Split(out, "-")
	version := strings.Split(unameR[0], ".")
	versionS, _ := strconv.ParseFloat(version[0]+"."+version[1], 64)
	return versionS
}

func setConntrackTable(buckets int, max int) {

	bash := &utils.Bash{
		Command: fmt.Sprintf("cat %s", CONNTRACK_MAX_PATH),
		Sudo:    true,
	}

	_, currentSize, _, err := bash.RunWithReturn()
	utils.PanicOnError(err)

	currentSizeInt, _ := strconv.Atoi(strings.Trim(currentSize, "\n"))

	if currentSizeInt >= max {
		log.Debugf("current conntrack table size %d >= %d, remain unchanged", currentSizeInt, max)
		return
	}

	log.Debugf("set CONNTRACK_BUCKETS=%d CONNTRACK_MAX=%d", buckets, max)

	ver := getKernelVersion()
	bucketsPath := CONNTRACK_BUCKETS_PATH

	if ver > 4.8 {
		bucketsPath = CONNTRACK_BUCKETS_PATH_48
	}

	b := &utils.Bash{
		Command: fmt.Sprintf("echo %d > %s && echo %d > %s", buckets, bucketsPath, max, CONNTRACK_MAX_PATH),
		Sudo:    true,
	}

	b.Run()
}

func PerformanceEntryPoint() {
	setConntrackTable(CONNTRACK_BUCKETS, CONNTRACK_MAX)
}
