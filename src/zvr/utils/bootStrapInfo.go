package utils

import (
	"fmt"
	"io/ioutil"
	log "github.com/Sirupsen/logrus"
	"encoding/json"
	"net"
	"strings"
)

const (
	BOOTSTRAP_INFO_CACHE = "/home/vyos/zvr/bootstrap-info.json"
	DEFAULT_SSH_PORT = 22
	VYOSHA_DEFAULT_ROUTE_SCRIPT = "/home/vyos/zvr/keepalived/script/defaultroute.sh"
)

const  (
	NOHA = "NoHa"
	HAMASTER = "Master"
	HABACKUP = "Backup"

	APPLIANCETYPE_SLB = "SLB"
	APPLIANCETYPE_VPC = "vpcvrouter"
)

var bootstrapInfo map[string]interface{} = make(map[string]interface{})

func GetSshPortFromBootInfo() float64 {
	port, ok := bootstrapInfo["sshPort"].(float64)
	if !ok {
		return DEFAULT_SSH_PORT
	}

	return port
}

func GetMgmtInfoFromBootInfo() map[string]interface{} {
	mgmtNic := bootstrapInfo["managementNic"].(map[string]interface{})
	return mgmtNic
}

func IsSkipVyosIptables() bool {
	if IsSLB() {
		/* SLB use iptables replace vyos firewall */
		return true
	}

	SkipVyosIptables, ok := bootstrapInfo["SkipVyosIptables"].(bool)
	if !ok {
		return false
	}

	return SkipVyosIptables
}

func IsConfigTcForVipQos() bool {
	ConfigTcForVipQos, ok := bootstrapInfo["ConfigTcForVipQos"].(bool)
	if !ok {
		/* for upgraded vpc, there is no ConfigTcForVipQos in bootstrapinfo before it reboot */
		return true
	}
	
	return ConfigTcForVipQos
}

func InitBootStrapInfo() {
	content, err := ioutil.ReadFile(BOOTSTRAP_INFO_CACHE); PanicOnError(err)
	if len(content) == 0 {
		log.Debugf("no content in %s, can not get mgmt gateway", BOOTSTRAP_INFO_CACHE)
	}

	if err := json.Unmarshal(content, &bootstrapInfo); err != nil {
		log.Debugf("can not parse info from %s, can not get mgmt gateway", BOOTSTRAP_INFO_CACHE)
	}
}

func IsHaEnabled() bool {
	if _, ok := bootstrapInfo["haStatus"]; ok {
		if !strings.EqualFold(bootstrapInfo["haStatus"].(string), NOHA) {
			return true
		}
	}

	return false
}

func GetVirtualRouterUuid()  string {
	if _, ok := bootstrapInfo["uuid"]; ok {
		return bootstrapInfo["uuid"].(string)
	}

	return ""
}

func GetBootStrapNicInfo() map[string]Nic {
	bootstrapNics := make(map[string]Nic)
	mgmtNic := bootstrapInfo["managementNic"].(map[string]interface{})
	if mgmtNic != nil {
		name, ok1 := mgmtNic["deviceName"].(string)
		mac, ok2 := mgmtNic["mac"].(string)
		ip, ok3 := mgmtNic["ip"].(string)
		if ok1 && ok2 && ok3 {
			mnic := Nic{Name: name, Mac: mac, Ip: ip}
			bootstrapNics[mnic.Name] = mnic
		}
	}

	otherNics := bootstrapInfo["additionalNics"].([]interface{})
	if otherNics != nil {
		for _, o := range otherNics {
			onic := o.(map[string]interface{})
			name, ok1 := onic["deviceName"].(string)
			mac, ok2 := onic["mac"].(string)
			ip, ok3 := onic["ip"].(string)
			if ok1 && ok2 && ok3 {
				additionalNic := Nic{Name: name, Mac: mac, Ip: ip}
				bootstrapNics[additionalNic.Name] = additionalNic
			}
		}
	}

	return bootstrapNics
}

func IsInManagementCidr(vipStr string) bool {
	mgmtNic := bootstrapInfo["managementNic"].(map[string]interface{})
	ipStr, _ := mgmtNic["ip"].(string)
	netmaskStr, _ := mgmtNic["netmask"].(string)

	ip := net.ParseIP(ipStr)
	netmask := net.IPMask(net.ParseIP(netmaskStr).To4())

	cidr := net.IPNet{IP:ip, Mask:netmask}

	vip := net.ParseIP(vipStr)
	return cidr.Contains(vip)
}

func GetMnNodeIps() map[string]string {
	mnNodeIps := make(map[string]string)
	mnNodeIp := bootstrapInfo["managementNodeIp"]
	if mnNodeIp != nil {
		mnNodeIpStr := mnNodeIp.(string)
		mnNodeIps[mnNodeIpStr] = mnNodeIpStr
	}

	mnPeerNodeIp := bootstrapInfo["managementPeerNodeIp"]
	if mnPeerNodeIp != nil {
		mnPeerNodeStr := mnPeerNodeIp.(string)
		mnNodeIps[mnPeerNodeStr] = mnPeerNodeStr
	}

	return mnNodeIps
}

func WriteDefaultHaScript(defaultNic *Nic)  {
	defaultNicName, err := GetNicNameByMac(defaultNic.Mac); PanicOnError(err)
	conent := ""
	if defaultNic.Gateway != "" {
		conent += fmt.Sprintln(fmt.Sprintf("ip route add default %s via %s || true", defaultNic.Gateway, defaultNicName))
	}

	if defaultNic.Gateway6 != "" {
		conent += fmt.Sprintln(fmt.Sprintf("ip -6 route add default %s via %s || true", defaultNic.Gateway6, defaultNicName))
	}

	err = ioutil.WriteFile(VYOSHA_DEFAULT_ROUTE_SCRIPT, []byte(conent), 0755); PanicOnError(err)
}

func IsSLB() bool {
	applianceType, found := bootstrapInfo["applianceVmSubType"]
	if !found {
		return false
	}
	return applianceType.(string) == APPLIANCETYPE_SLB
}