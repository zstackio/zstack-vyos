package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"zstack-vyos/utils"

	log "github.com/sirupsen/logrus"
)

func (bs *IpvsHealthCheckBackendServer) doUdpCheck() {
	addr := bs.BackendIp
	ip := net.ParseIP(bs.BackendIp)
	if ip != nil && ip.To4() == nil {
		addr = fmt.Sprintf("[%s]", addr)
	}
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", addr, bs.HealthCheckPort),
		time.Duration(bs.HealthCheckTimeout)*time.Second)
	if err != nil {
		log.Debugf("[udp checher]: dial udp  %s:%d failed: %v", addr, bs.HealthCheckPort, err)
		bs.result <- false
		return
	}

	defer conn.Close()
	message := []byte("zstack ipvs health check from" + bs.FrontPort + "" + bs.FrontPort)

	_, err = conn.Write(message)
	if err != nil {
		log.Debugf("[udp checher]: send  udp message to %s:%d failed: %v", bs.BackendIp, bs.HealthCheckPort, err)
		bs.result <- false
		return
	}

	buffer := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(time.Duration(bs.HealthCheckTimeout) * time.Second))
	_, err = conn.Read(buffer)
	if err != nil {
		log.Debugf("[udp checher]: recv udp message from %s:%d failed: %v", bs.BackendIp, bs.HealthCheckPort, err)

		if !strings.Contains(err.Error(), "i/o timeout") {
			bs.result <- false
			return
		}

		cmd := fmt.Sprintf("ping %s -c 1 -t 1", bs.BackendIp)
		if strings.Contains(bs.BackendIp, ":") {
			cmd = fmt.Sprintf("ping6 %s -c 1 -t 1", bs.BackendIp)
		}

		b := utils.Bash{
			Command: cmd,
			Sudo:    true,
		}
		ret, _, _, err := b.RunWithReturn()
		if err != nil || ret != 0 {
			bs.result <- false
		} else {
			bs.result <- true
		}
	} else {
		log.Debugf("[udp checher]: recv udp message from %s:%s, result:%s", bs.BackendIp, bs.HealthCheckPort, buffer)
		bs.result <- true
	}
}
