package plugin

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/zstackio/zstack-vyos/utils"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
)

// the name of metric data label
const (
	LABEL_CPU      = "cpu"
	LABEL_CPU_TYPE = "type"

	LABEL_MEMORY = "memory"

	LABEL_FILESYSTEM_DEVOCE     = "device"
	LABEL_FILESYSTEM_FSTYPE     = "fstype"
	LABEL_FILESYSTEM_MOUNTPOINT = "mountpoint"
	LABEL_FILESYSTEM_TYPE       = "type"
)

type vpcOsCollector struct {
	vpcCpuUsage    *prom.Desc
	vpcMemoryUsage *prom.Desc
	vpcDiskUsage   *prom.Desc
}

func (c *vpcOsCollector) Describe(ch chan<- *prom.Desc) error {
	ch <- c.vpcCpuUsage
	ch <- c.vpcMemoryUsage
	ch <- c.vpcDiskUsage
	return nil
}

func (c *vpcOsCollector) Update(ch chan<- prom.Metric) error {
	//mem_available = (signed long)kb_main_free - watermark_low
	//      + kb_inactive_file + kb_active_file - MIN((kb_inactive_file + kb_active_file) / 2, watermark_low)
	//      + kb_slab_reclaimable - MIN(kb_slab_reclaimable / 2, watermark_low);
	memInfo := getVPCMemInfo()
	if memInfo != nil {
		ch <- prom.MustNewConstMetric(c.vpcMemoryUsage, prom.GaugeValue, float64(memInfo.kb_MemUsed*1024), "used")
		ch <- prom.MustNewConstMetric(c.vpcMemoryUsage, prom.GaugeValue, float64((memInfo.kb_Memfree)*1024), "free")
		ch <- prom.MustNewConstMetric(c.vpcMemoryUsage, prom.GaugeValue, float64((memInfo.kb_Buffer)*1024), "buffered")
		ch <- prom.MustNewConstMetric(c.vpcMemoryUsage, prom.GaugeValue, float64((memInfo.kb_Cached)*1024), "cached")
		ch <- prom.MustNewConstMetric(c.vpcMemoryUsage, prom.GaugeValue, float64((memInfo.kb_Memtotal)*1024), "total")
		ch <- prom.MustNewConstMetric(c.vpcMemoryUsage, prom.GaugeValue, float64(memInfo.kb_Available*1024), "available")
	}

	cpus := getVPCCpuInfo()
	if cpus != nil {
		for _, cpu := range cpus {
			ch <- prom.MustNewConstMetric(c.vpcCpuUsage, prom.GaugeValue, cpu.user, cpu.cpu, "user")
			ch <- prom.MustNewConstMetric(c.vpcCpuUsage, prom.GaugeValue, cpu.nice, cpu.cpu, "nice")
			ch <- prom.MustNewConstMetric(c.vpcCpuUsage, prom.GaugeValue, cpu.system, cpu.cpu, "system")
			ch <- prom.MustNewConstMetric(c.vpcCpuUsage, prom.GaugeValue, cpu.idle, cpu.cpu, "idle")
			ch <- prom.MustNewConstMetric(c.vpcCpuUsage, prom.GaugeValue, cpu.iowait, cpu.cpu, "iowait")
			ch <- prom.MustNewConstMetric(c.vpcCpuUsage, prom.GaugeValue, cpu.irq, cpu.cpu, "irq")
			ch <- prom.MustNewConstMetric(c.vpcCpuUsage, prom.GaugeValue, cpu.softirq, cpu.cpu, "softirq")
		}
	}

	disks := getDiskCpuInfo()
	if disks != nil {
		for _, disk := range disks {
			ch <- prom.MustNewConstMetric(c.vpcDiskUsage, prom.GaugeValue, disk.total, disk.device, disk.mountpoint, disk.fstype, "total")
			ch <- prom.MustNewConstMetric(c.vpcDiskUsage, prom.GaugeValue, disk.used, disk.device, disk.mountpoint, disk.fstype, "used")
			ch <- prom.MustNewConstMetric(c.vpcDiskUsage, prom.GaugeValue, disk.free, disk.device, disk.mountpoint, disk.fstype, "free")
			ch <- prom.MustNewConstMetric(c.vpcDiskUsage, prom.GaugeValue, disk.usedPercent, disk.device, disk.mountpoint, disk.fstype, "usedPercent")
			ch <- prom.MustNewConstMetric(c.vpcDiskUsage, prom.GaugeValue, disk.freePercent, disk.device, disk.mountpoint, disk.fstype, "freePercent")
		}
	}

	return nil
}

func NewVpcOsPrometheusCollector() MetricCollector {
	return &vpcOsCollector{
		vpcCpuUsage: prom.NewDesc(
			"vpcCpuUsage",
			"vpcCpuUsage VPC Router Cpu usage statistic",
			[]string{LABEL_CPU, LABEL_CPU_TYPE}, nil,
		),
		vpcMemoryUsage: prom.NewDesc(
			"vpcMemoryUsage",
			"vpcMemoryUsage VPC Router memory usage statistic",
			[]string{LABEL_MEMORY}, nil,
		),
		vpcDiskUsage: prom.NewDesc(
			"vpcDiskUsage",
			"vpcDiskUsage VPC Router disk usage statistic",
			[]string{LABEL_FILESYSTEM_DEVOCE, LABEL_FILESYSTEM_MOUNTPOINT, LABEL_FILESYSTEM_FSTYPE, LABEL_FILESYSTEM_TYPE}, nil,
		),
	}
}

func init() {
	RegisterPrometheusCollector(NewVpcOsPrometheusCollector())
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
	kb_SlabTotal       uint64
	kb_MemUsed         uint64
	kb_Available       uint64
}

func getWaterMark_Low() uint64 {
	infoFromFile, err := ioutil.ReadFile("/proc/sys/vm/min_free_kbytes")
	if err != nil {
		log.Error(err.Error())
		return 0
	}

	kb_min_free, _ := strconv.ParseUint(strings.Trim(string(infoFromFile), " "), 10, 64)

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
func getVPCMemInfo() *memInfo {
	infoFromFile, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		log.Error(err.Error())
		return nil
	}
	stdout := string(infoFromFile)

	reg := regexp.MustCompile(`\s+`)
	lines := strings.Split(stdout, "\n")

	var memInfos memInfo
	memInfos.watermark_low = getWaterMark_Low()
	for _, line := range lines {
		strs := reg.Split(strings.TrimSpace(line), -1)
		strs[0] = strings.Trim(strs[0], ":")
		if strs[0] == "MemTotal" {
			memInfos.kb_Memtotal, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if strs[0] == "MemFree" {
			memInfos.kb_Memfree, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if strs[0] == "Buffers" {
			memInfos.kb_Buffer, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if strs[0] == "Cached" {
			memInfos.kb_Cached, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if strs[0] == "Active(file)" {
			memInfos.kb_ActiveFile, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if strs[0] == "Inactive(file)" {
			memInfos.kb_InactiveFile, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if strs[0] == "SReclaimable" {
			memInfos.kb_SlabReclaimable, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		} else if strs[0] == "Slab:" {
			memInfos.kb_SlabTotal, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
		}
	}

	memInfos.kb_Available = memInfos.kb_Memfree - memInfos.watermark_low +
		memInfos.kb_InactiveFile + memInfos.kb_ActiveFile + min((memInfos.kb_ActiveFile+memInfos.kb_InactiveFile)/2, memInfos.watermark_low) +
		memInfos.kb_SlabReclaimable + min(memInfos.kb_SlabReclaimable/2, memInfos.watermark_low)

	memInfos.kb_MemUsed = memInfos.kb_Memtotal - memInfos.kb_Available

	return &memInfos
}

type cpuInfo struct {
	cpu string

	user       float64
	nice       float64
	system     float64
	idle       float64
	iowait     float64
	irq        float64
	softirq    float64
	steal      float64
	guest      float64
	guest_nice float64

	total float64
}

/*
output example
root@vyos:/home/vyos# cat /proc/stat
cpu  2519025 0 6192013 4369956549 103010 1841 180690 0 0 0
cpu0 645751 0 1635386 1088883029 89763 1841 155834 0 0 0
cpu1 624334 0 1512009 1093732377 7040 0 8665 0 0 0
cpu2 628977 0 1556558 1093526709 3767 0 7735 0 0 0
cpu3 619963 0 1488060 1093814434 2440 0 8456 0 0 0
intr 2282219413 152 368 0 0 9 0 2 0 0 3 0 1096906 822 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 873503192 279 0 8192200 0 263993 28 0 3833769 81 0
.......
ref: https://www.kgoettler.com/post/proc-stat/
ref: https://elixir.bootlin.com/linux/latest/source/fs/proc/stat.c
*/
func getVPCCpuInfo() []*cpuInfo {
	infoFromFile, err := ioutil.ReadFile("/proc/stat")
	if err != nil {
		log.Errorf("read /proc/stat failed: %v", err)
		return nil
	}
	stdout := string(infoFromFile)

	lines := strings.Split(stdout, "\n")

	var cpuInfos []*cpuInfo
	for _, line := range lines {
		items := strings.Split(line, " ")
		if items[0] == "cpu" {
			continue
		}

		if !strings.Contains(items[0], "cpu") {
			break
		}

		usage := cpuInfo{cpu: items[0]}
		usage.user, _ = strconv.ParseFloat(strings.Trim(items[1], " "), 64)
		usage.nice, _ = strconv.ParseFloat(strings.Trim(items[2], " "), 64)
		usage.system, _ = strconv.ParseFloat(strings.Trim(items[3], " "), 64)
		usage.idle, _ = strconv.ParseFloat(strings.Trim(items[4], " "), 64)
		usage.iowait, _ = strconv.ParseFloat(strings.Trim(items[5], " "), 64)
		usage.irq, _ = strconv.ParseFloat(strings.Trim(items[6], " "), 64)
		usage.softirq, _ = strconv.ParseFloat(strings.Trim(items[7], " "), 64)
		usage.steal, _ = strconv.ParseFloat(strings.Trim(items[8], " "), 64)
		usage.guest, _ = strconv.ParseFloat(strings.Trim(items[9], " "), 64)
		usage.guest_nice, _ = strconv.ParseFloat(strings.Trim(items[10], " "), 64)

		usage.total = usage.user + usage.nice + usage.system + usage.idle + usage.iowait + usage.irq + usage.softirq + usage.steal

		if usage.total == 0 {
			log.Debugf("getDiskCpuInfo line %s, items: %+v", line, items)
			continue
		}

		usage.user = 100 * (usage.user / usage.total)
		usage.nice = 100 * (usage.nice / usage.total)
		usage.system = 100 * (usage.system / usage.total)
		usage.idle = 100 * (usage.idle / usage.total)
		usage.iowait = 100 * (usage.iowait / usage.total)
		usage.irq = 100 * (usage.irq / usage.total)
		usage.softirq = 100 * (usage.softirq / usage.total)

		cpuInfos = append(cpuInfos, &usage)
	}

	return cpuInfos
}

type diskInfo struct {
	device     string
	fstype     string
	mountpoint string

	total       float64
	used        float64
	usedPercent float64
	free        float64
	freePercent float64
	available   float64
}

/*
output example
root@vyos:/home/vyos# df -h -B 1 | grep vda1
/dev/vda1            8320868352 822415360 7052181504  11% /
*/
func getDiskCpuInfo() []*diskInfo {
	bash := &utils.Bash{
		Command: fmt.Sprintf("df -h -l -B 1 | grep -e '^/dev/.da'"),
		NoLog:   true,
	}
	ret, stdout, _, _ := bash.RunWithReturn()
	if ret != 0 {
		return nil
	}

	reg := regexp.MustCompile(`\s+`)

	var diskInfos []*diskInfo
	lines := strings.Split(strings.Trim(stdout, "\n"), "\n")
	for _, line := range lines {
		var usage diskInfo
		items := reg.Split(strings.TrimSpace(line), -1)
		if len(items) < 5 {
			continue
		}

		for i, item := range items {
			switch i {
			case 1:
				if num, err := strconv.ParseFloat(strings.Trim(item, " "), 64); err == nil {
					usage.total = num
				}
			case 2:
				if num, err := strconv.ParseFloat(strings.Trim(item, " "), 64); err == nil {
					usage.used = num
				}
			case 3:
				if num, err := strconv.ParseFloat(strings.Trim(item, " "), 64); err == nil {
					usage.available = num
				}
			case 4:
				num := strings.Trim(item, " ")
				num = strings.Replace(num, "%", "", 1)
				if num, err := strconv.ParseFloat(num, 64); err == nil {
					usage.usedPercent = num
				}
			}
		}

		if usage.total == 0 {
			log.Debugf("getDiskCpuInfo line %s, items: %+v", line, items)
			continue
		}

		usage.free = usage.total - usage.used
		usage.freePercent = 100 - usage.usedPercent

		disks := strings.Split(strings.Trim(items[0], "/"), "/")
		if len(disks) < 2 {
			log.Debugf("getDiskCpuInfo disks %s, items: %+v", disks, items[0])
			continue
		}

		usage.device = disks[1]
		usage.fstype = "ext4"
		usage.mountpoint = "/"
		diskInfos = append(diskInfos, &usage)
	}

	return diskInfos
}

func min(x, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}
