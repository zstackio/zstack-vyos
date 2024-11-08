package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"zstack-vyos/plugin"
	"zstack-vyos/utils"

	log "github.com/sirupsen/logrus"
)

type IpvsHealthCheckBackendServer struct {
	status     bool
	successCnt uint
	failedCnt  uint
	cancel     context.CancelFunc
	result     chan bool
	plugin.IpvsHealthCheckBackendServer
}

var logFile string
var confFile string
var pidFile string

var gHealthCheckMap map[string]*IpvsHealthCheckBackendServer
var gHealthCheckMapLock sync.Mutex
var ipvsadmLock sync.Mutex

func parseCommandOptions() {
	flag.StringVar(&logFile, "log", plugin.IPVS_HEALTH_CHECK_LOG_FILE, "ipvs health check The log file path")
	flag.StringVar(&confFile, "f", plugin.IPVS_HEALTH_CHECK_CONFIG_FILE, "ipvs health check config file path")
	flag.StringVar(&pidFile, "p", plugin.IPVS_HEALTH_CHECK_PID_FILE, "ipvs health check pid file path")

	flag.Parse()
}

func (bs *IpvsHealthCheckBackendServer) getBackendKey() string {
	proto := "udp"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "tcp"
	}

	return proto + "-" + bs.FrontIp + "-" + bs.FrontPort + "-" + bs.BackendIp + "-" + bs.BackendPort
}

func (bs *IpvsHealthCheckBackendServer) equal(other *IpvsHealthCheckBackendServer) bool {
	return bs.ConnectionType == other.ConnectionType &&
		bs.ProtocolType == other.ProtocolType &&
		bs.Scheduler == other.Scheduler &&
		bs.FrontIp == other.FrontIp &&
		bs.FrontPort == other.FrontPort &&
		bs.Weight == other.Weight &&
		bs.BackendIp == other.BackendIp &&
		bs.BackendPort == other.BackendPort &&
		bs.HealthCheckProtocol == other.HealthCheckProtocol &&
		bs.HealthCheckPort == other.HealthCheckPort &&
		bs.MaxConnection == other.MaxConnection &&
		bs.MinConnection == other.MinConnection
}

func (bs *IpvsHealthCheckBackendServer) doHealthCheck() {
	if bs.HealthCheckProtocol == "udp" {
		bs.doUdpCheck()
	} else {
		log.Debugf("unknow health check protocol %s", bs.HealthCheckProtocol)
		bs.result <- false
	}
}

func (bs *IpvsHealthCheckBackendServer) Install() {
	ipvsadmLock.Lock()
	defer ipvsadmLock.Unlock()
	bs.status = true

	proto := "-u"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "-t"
	}
	frontIp := bs.FrontIp
	ip := net.ParseIP(frontIp)
	if ip != nil && ip.To4() == nil {
		frontIp = fmt.Sprintf("[%s]", frontIp)
	}
	backedIp := bs.BackendIp
	ip = net.ParseIP(backedIp)
	if ip != nil && ip.To4() == nil {
		backedIp = fmt.Sprintf("[%s]", backedIp)
	}

	cmd := fmt.Sprintf("(ipvsadm -L %s %s:%s || ipvsadm -A %s %s:%s -s %s); "+
		"ipvsadm -a %s %s:%s -r  %s:%s %s -w %s -x %d -y %d",
		proto, frontIp, bs.FrontPort,
		proto, frontIp, bs.FrontPort, bs.Scheduler,
		proto, frontIp, bs.FrontPort, backedIp, bs.BackendPort, bs.ConnectionType, bs.Weight, bs.MaxConnection, bs.MinConnection)

	b := utils.Bash{
		Command: cmd,
		Sudo:    true,
	}

	b.Run()
}

func (bs *IpvsHealthCheckBackendServer) UnInstall() {
	ipvsadmLock.Lock()
	defer ipvsadmLock.Unlock()
	bs.status = false

	proto := "-u"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "-t"
	}
	frontIp := bs.FrontIp
	ip := net.ParseIP(frontIp)
	if ip != nil && ip.To4() == nil {
		frontIp = fmt.Sprintf("[%s]", frontIp)
	}
	backedIp := bs.BackendIp
	ip = net.ParseIP(backedIp)
	if ip != nil && ip.To4() == nil {
		backedIp = fmt.Sprintf("[%s]", backedIp)
	}

	cmd := fmt.Sprintf("ipvsadm -d %s %s:%s -r %s:%s", proto, frontIp, bs.FrontPort, backedIp, bs.BackendPort)
	b := utils.Bash{
		Command: cmd,
		Sudo:    true,
	}
	b.Run()

	/* if there is no backend, remove the service */
	conf, err := plugin.NewIpvsConfFromSave()
	if err != nil {
		log.Debugf("[ipvsHealthCheck] ipvsadm-save to config failed %+v", err)
	}

	for _, fs := range conf.Services {
		if len(fs.BackendServers) == 0 {
			proto := "-u"
			if strings.ToLower(fs.ProtocolType) == "tcp" || strings.ToLower(fs.ProtocolType) == "-t" {
				proto = "-t"
			}
			frontIp := fs.FrontIp
			ip := net.ParseIP(frontIp)
			if ip != nil && ip.To4() == nil {
				frontIp = fmt.Sprintf("[%s]", frontIp)
			}

			cmd := fmt.Sprintf("ipvsadm -D %s %s:%s", proto, frontIp, fs.FrontPort)
			b := utils.Bash{
				Command: cmd,
				Sudo:    true,
			}
			b.Run()
		}
	}

}

func (bs *IpvsHealthCheckBackendServer) EditBackendServer() {
	ipvsadmLock.Lock()
	defer ipvsadmLock.Unlock()

	proto := "-u"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "-t"
	}
	frontIp := bs.FrontIp
	ip := net.ParseIP(frontIp)
	if ip != nil && ip.To4() == nil {
		frontIp = fmt.Sprintf("[%s]", frontIp)
	}
	backedIp := bs.BackendIp
	ip = net.ParseIP(backedIp)
	if ip != nil && ip.To4() == nil {
		backedIp = fmt.Sprintf("[%s]", backedIp)
	}

	cmd := fmt.Sprintf("ipvsadm -e %s %s:%s -r  %s:%s %s -w %s -x %d -y %d",
		proto, frontIp, bs.FrontPort, backedIp, bs.BackendPort, bs.ConnectionType, bs.Weight, bs.MaxConnection, bs.MinConnection)

	b := utils.Bash{
		Command: cmd,
		Sudo:    true,
	}
	b.Run()
}

func (bs *IpvsHealthCheckBackendServer) EditFrontService() {
	ipvsadmLock.Lock()
	defer ipvsadmLock.Unlock()

	proto := "-u"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "-t"
	}
	frontIp := bs.FrontIp
	ip := net.ParseIP(frontIp)
	if ip != nil && ip.To4() == nil {
		frontIp = fmt.Sprintf("[%s]", frontIp)
	}

	cmd := fmt.Sprintf("ipvsadm -E %s %s:%s -s %s", proto, frontIp, bs.FrontPort, bs.Scheduler)
	b := utils.Bash{
		Command: cmd,
		Sudo:    true,
	}
	b.Run()
}

func (bs *IpvsHealthCheckBackendServer) setStatus(status bool) {
	bs.status = status
	bs.failedCnt = 0
	bs.successCnt = 0
}

func (bs *IpvsHealthCheckBackendServer) Start() {
	defer func() {
		if err := recover(); err != nil {
			/* run failed, start again */
			log.Infof("[ipvsHealthCheck task] run failed %+v", err)
			go bs.Start()
		}
	}()

	/*
		health check task is loop task: wait for following events:
		1. timer to do health check in another go routine
		2. health check result  ---- wait resulrt from #1
		3. backend server removed -- stopped the health check task
	*/

	taskTimer := time.NewTimer(time.Duration(bs.HealthCheckInterval) * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	bs.cancel = cancel
	bs.result = make(chan bool, 1)
	bs.status = false
	bs.successCnt = 0
	bs.failedCnt = 0

	log.Debugf("[ipvsHealthCheck task] start health check task for %s", bs.getBackendKey())
	for {
		select {
		case result := <-bs.result:
			if result {
				if bs.successCnt == math.MaxUint-1 {
					bs.successCnt = bs.HealthyThreshold
				} else {
					bs.successCnt++
				}

				bs.failedCnt = 0
			} else {
				if bs.failedCnt == math.MaxUint-1 {
					bs.failedCnt = bs.UnhealthyThreshold
				} else {
					bs.failedCnt++
				}
				bs.successCnt = 0
			}

			log.Debugf("[ipvsHealthCheck task] %s: healthcheck resut:%v, current status %v:  successCnt: %d,%d failedCnt: %d:%d",
				bs.getBackendKey(), result, bs.status,
				bs.successCnt, bs.HealthyThreshold,
				bs.failedCnt, bs.UnhealthyThreshold)
			if bs.failedCnt >= bs.UnhealthyThreshold && bs.status {
				bs.UnInstall()
			} else if bs.successCnt >= bs.HealthyThreshold && !bs.status {
				bs.Install()
			}
			taskTimer.Reset(time.Duration(bs.HealthCheckInterval) * time.Second)

		case <-ctx.Done():
			log.Debugf("[ipvsHealthCheck task] stop health check task for %s", bs.getBackendKey())
			taskTimer.Stop()
			return

		case <-taskTimer.C:
			// avoid to call DoHealthCheck while previous call is not finished
			log.Debugf("[ipvsHealthCheck task] timer expired for health check task %s", bs.getBackendKey())
			go bs.doHealthCheck()
		}
	}
}

func (bs *IpvsHealthCheckBackendServer) Stop() {
	log.Debugf("[ipvsHealthCheck task] stop health check task for %s", bs.getBackendKey())
	bs.cancel()
	bs.UnInstall()
}

func reloadIpvsHealthCheckConfig() {
	defer func() {
		if err := recover(); err != nil {
			log.Infof("[ipvsHealthCheck reload] load config failed %+v", err)
		}
	}()

	var conf plugin.IpvsHealthCheckConf
	err := utils.JsonLoadConfig(confFile, &conf)
	if err != nil {
		log.Debugf("[ipvsHealthCheck reload] load config failed %v", err)
		return
	}

	log.Debugf("[ipvsHealthCheck reload] load config file success, %++v", conf)
	checkers := map[string]*IpvsHealthCheckBackendServer{}
	if conf.Services != nil {
		for _, fs := range conf.Services {
			log.Debugf("[ipvsHealthCheck reload] new Services: %+v", fs)
			for _, bs := range fs.BackendServers {
				nc := IpvsHealthCheckBackendServer{
					/*  health check will not install ipvs service, untill  backend is up */
					status:                       false,
					IpvsHealthCheckBackendServer: *bs,
				}

				log.Debugf("[ipvsHealthCheck reload] new checker: %+v", nc)
				checkers[nc.getBackendKey()] = &nc
			}
		}
	}

	gHealthCheckMapLock.Lock()
	defer gHealthCheckMapLock.Unlock()

	var toDeleted []string
	for _, old := range gHealthCheckMap {
		log.Debugf("[ipvsHealthCheck reload] old checker: %+v", old)
		check, found := checkers[old.getBackendKey()]
		if !found {
			log.Debugf("[ipvsHealthCheck reload] delete health check task for %s", old.getBackendKey())
			toDeleted = append(toDeleted, old.getBackendKey())
		} else {
			/* 后端服务器的health check task 参数可能变化, 有两种处理方式:
			1. copy health check配置参数给old
			2. copy old health check的状态参数给new,
			此处采用#1 */
			log.Debugf("[ipvsHealthCheck reload] update health check task params %+v", check.IpvsHealthCheckBackendServer)
			if !old.equal(check) {
				if old.Scheduler != check.Scheduler {
					old.CopyParamsFrom(&check.IpvsHealthCheckBackendServer)
					go old.EditFrontService()
				} else {
					old.CopyParamsFrom(&check.IpvsHealthCheckBackendServer)
					go old.EditBackendServer()
				}
			} else {
				log.Debugf("[ipvsHealthCheck reload] checker: %s not changed", old.getBackendKey())
			}

		}
	}

	for _, key := range toDeleted {
		log.Debugf("[ipvsHealthCheck reload] delete health check task for %s", key)
		go gHealthCheckMap[key].Stop()
		delete(gHealthCheckMap, key)
	}

	/* new backend health check */
	for _, check := range checkers {
		_, found := gHealthCheckMap[check.getBackendKey()]
		if !found {
			log.Debugf("[ipvsHealthCheck reload] add new health check task %+v", check.getBackendKey())
			gHealthCheckMap[check.getBackendKey()] = check
			go check.Start()
		}
	}
}

func writePidToFile(pidFilePath string) error {
	pid := os.Getpid()
	pidStr := strconv.Itoa(pid)

	file, err := os.Create(pidFilePath)
	if err != nil {
		return fmt.Errorf("can not create pid file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(pidStr + "\n")
	if err != nil {
		return fmt.Errorf("can not write pid file: %v", err)
	}

	return nil
}

func syncIpvsadmWithHealthCheck() {
	defer func() {
		if err := recover(); err != nil {
			log.Infof("[ipvsHealthCheck sync] sync ipvsadm failed %+v", err)
		}
	}()

	conf, err := plugin.NewIpvsConfFromSave()
	if err != nil {
		log.Debugf("[ipvsHealthCheck sync] ipvsadm-save to config failed %+v", err)
	}

	gHealthCheckMapLock.Lock()
	defer gHealthCheckMapLock.Unlock()

	tempBsMap := map[string]*IpvsHealthCheckBackendServer{}
	for _, fs := range conf.Services {
		log.Debugf("[ipvsHealthCheck sync] ipvsadm-save front end service %+v", fs)
		for _, bs := range fs.BackendServers {
			log.Debugf("[ipvsHealthCheck sync] 	ipvsadm-save backend end server %+v", bs)

			temp := IpvsHealthCheckBackendServer{}
			temp.ProtocolType = "udp"
			if strings.ToLower(fs.ProtocolType) == "tcp" || strings.ToLower(fs.ProtocolType) == "-t" {
				temp.ProtocolType = "tcp"
			}
			temp.FrontIp = fs.FrontIp
			temp.FrontPort = fs.FrontPort
			temp.BackendIp = bs.BackendIp
			temp.BackendPort = bs.BackendPort

			tempBsMap[temp.getBackendKey()] = &temp

			if gHealthCheckMap[temp.getBackendKey()] == nil {
				log.Debugf("[ipvsHealthCheck sync] delete backend server %+v", temp.getBackendKey())
				go temp.UnInstall()
			} else if !gHealthCheckMap[temp.getBackendKey()].status {
				log.Debugf("[ipvsHealthCheck sync] change backend server %+v status up", temp.getBackendKey())
				gHealthCheckMap[temp.getBackendKey()].setStatus(true)
			}
		}
	}

	for _, gbs := range gHealthCheckMap {
		if tempBsMap[gbs.getBackendKey()] == nil {
			log.Debugf("[ipvsHealthCheck sync] change backend server %+v status down", gbs.getBackendKey())
			gbs.setStatus(false)
		}
	}
}

// when vpcha master/backup failover, we need to make
func fastUpBackendServers() {
	gHealthCheckMapLock.Lock()
	defer gHealthCheckMapLock.Unlock()

	for _, gbs := range gHealthCheckMap {
		// set false, when health check finished, it will install backend server
		gbs.setStatus(false)
		go gbs.doHealthCheck()
	}
}

func main() {
	parseCommandOptions()
	utils.InitLog(logFile, utils.IsRuingUT())
	utils.InitVyosVersion()

	pid, _ := utils.ReadPid(pidFile)
	if pid != 0 {
		if utils.ProcessExists(pid) == nil {
			log.Debugf("[ipvsHealthCheck] already running, pid %d", pid)
			return
		}
	}
	err := writePidToFile(pidFile)
	if err != nil {
		log.Debugf("[ipvsHealthCheck] write pid[%d] to file failed, err %v", pid, err)
	}

	gHealthCheckMap = map[string]*IpvsHealthCheckBackendServer{}

	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, syscall.SIGHUP, syscall.SIGUSR1)

	syncTimer := time.NewTimer(time.Duration(300) * time.Second)

	/* push a signal when start process */
	interruptChan <- syscall.SIGHUP

	/* main thead loop handles 2 events:
	1. realod config
	2. sync ipvs-admin timer
	*/
	for {
		select {
		case sig := <-interruptChan:
			if sig == syscall.SIGHUP {
				reloadIpvsHealthCheckConfig()
			} else if sig == syscall.SIGUSR1 {
				fastUpBackendServers()
			} else {
				log.Debugf("[ipvsHealthCheck] unknow sig %+v", sig)
			}

		case <-syncTimer.C:
			/* sync ipvsadm-save */
			syncIpvsadmWithHealthCheck()

		}
	}
}

/* func for UT */
func stopIpvsConfig() {
	pid, err := utils.ReadPid(plugin.IPVS_HEALTH_CHECK_PID_FILE)
	utils.PanicOnError(err)
	/* reload config */
	b := utils.Bash{
		Command: fmt.Sprintf("kill -9 %d", pid),
		Sudo:    true,
	}
	err = b.Run()
	utils.PanicOnError(err)
}
