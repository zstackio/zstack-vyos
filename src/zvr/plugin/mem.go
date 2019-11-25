package plugin

import (
	log "github.com/Sirupsen/logrus"
	prom "github.com/prometheus/client_golang/prometheus"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"zvr/utils"
)

// the name of metric data label
const (
	LABEL_VPC_INSTANCE = "instance"
)
type memCollector struct {
	memAvailable *prom.Desc
	memUsed *prom.Desc

	vmUUids  string
	instance string
}

type memInfo struct {
	watermark_low      uint64
	kb_Memtotal        uint64
	kb_Memfree         uint64
	kb_Buffer          uint64
	kb_Cached          uint64
	kb_InactiveFile    uint64
	kb_ActiveFile      uint64
	kb_SlabReclaimable uint64
}

func (c *memCollector) Describe(ch chan<- *prom.Desc) error {
	ch <- c.memAvailable
	ch <- c.memUsed
	return nil
}

func NewMemPrometheusCollector() MetricCollector {
	return &memCollector{
		memAvailable: prom.NewDesc(
			"vpc_memory_available",
			"available memory of VPC in bytes",
			[]string{LABEL_VPC_INSTANCE}, nil,
		),
		memUsed: prom.NewDesc(
			"vpc_memory_used",
			"memory of VPC allocated and unable to free in bytes",
			[]string{LABEL_VPC_INSTANCE}, nil,
		),

	}
}

func init() {
	RegisterPrometheusCollector(NewMemPrometheusCollector())
}

func getWaterMark_Low() uint64{
	infoFromFile, err := ioutil.ReadFile("/proc/sys/vm/min_free_kbytes")
	if err != nil {
		log.Error(err.Error())
		return 0
	}

	kb_min_free, _ :=  strconv.ParseUint(strings.Trim(string(infoFromFile), " "), 10, 64)

	watermark_low := kb_min_free * 5 / 4 /* should be equal to sum of all 'low' fields in /proc/zoneinfo */

	return watermark_low
}

/*
output example
# cat /proc/meminfo'
MemTotal:        7990336 kB
MemFree:         1228584 kB
MemAvailable:    2973840 kB
Buffers:            1072 kB
Cached:          1970788 kB
*/
func getVPCMemInfo() (*memInfo) {
	infoFromFile, err := ioutil.ReadFile("/proc/meminfo")
	if (err != nil ){
		log.Error(err.Error())
		return nil
	}
	stdout := string(infoFromFile)

	reg := regexp.MustCompile(`\s+`)
	lines := strings.Split(stdout, "\n")

	var memInfos memInfo
	memInfos.watermark_low= getWaterMark_Low()
	for _, line := range lines {
		strs := reg.Split(strings.TrimSpace(line), -1)
		strs[0] = strings.Trim(strs[0], ":")
		if (strs[0] == "MemTotal") {
			memInfos.kb_Memtotal, _ =strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if (strs[0] == "MemFree") {
			memInfos.kb_Memfree, _ =strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if (strs[0] == "Buffers") {
			memInfos.kb_Buffer, _ =strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if (strs[0] == "Cached") {
			memInfos.kb_Cached, _ =strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if (strs[0] == "Active(file)") {
			memInfos.kb_Cached, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if (strs[0] == "Inactive(file)") {
			memInfos.kb_Cached, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if (strs[0] == "SReclaimable") {
			memInfos.kb_SlabReclaimable, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		}
	}

	return &memInfos
}

func (c *memCollector) Update(ch chan <- prom.Metric ) error  {
	//mem_available = (signed long)kb_main_free - watermark_low
	//      + kb_inactive_file + kb_active_file - MIN((kb_inactive_file + kb_active_file) / 2, watermark_low)
	//      + kb_slab_reclaimable - MIN(kb_slab_reclaimable / 2, watermark_low);
	memInfo := getVPCMemInfo()
	if memInfo != nil {
		return nil
	}
	kb_mem_available := memInfo.kb_Memfree - memInfo.watermark_low +
			memInfo.kb_InactiveFile + memInfo.kb_ActiveFile + min((memInfo.kb_ActiveFile + memInfo.kb_InactiveFile)/2, memInfo.watermark_low)+
			memInfo.kb_SlabReclaimable + min((memInfo.kb_SlabReclaimable / 2),memInfo.watermark_low)

	vpcUuid := utils.GetVirtualRouterUuid()

	ch <- prom.MustNewConstMetric(c.memUsed,prom.GaugeValue, float64((memInfo.kb_Memtotal - kb_mem_available)*1024),vpcUuid)
	ch <- prom.MustNewConstMetric(c.memAvailable,prom.GaugeValue, float64((kb_mem_available)*1024),vpcUuid)

	return nil
}

func min(x, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}