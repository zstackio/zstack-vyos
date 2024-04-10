package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	BOOTSTRAP_INFO_FILE     = "bootstrap-info.json"
	DEFAULT_SSH_PORT        = 22
	HA_DEFAULT_ROUTE_SCRIPT = "keepalived/script/defaultroute.sh"
)

const (
	NOHA     = "NoHa"
	HAMASTER = "Master"
	HABACKUP = "Backup"

	APPLIANCETYPE_SLB = "SLB"
	APPLIANCETYPE_VPC = "vpcvrouter"

	NIC_TYPE_PRIVATE = "Private"
	NIC_TYPE_PUBLIC  = "Public"
)

type NicInfo struct {
	Ip                    string `json:"ip"`
	Netmask               string `json:"netmask"`
	Gateway               string `json:"gateway"`
	Mac                   string `json:"Mac"`
	Category              string `json:"category"`
	L2Type                string `json:"l2type"`
	PhysicalInterface     string `json:"physicalInterface"`
	Vni                   int    `json:"vni"`
	FirewallDefaultAction string `json:"firewallDefaultAction"`
	Mtu                   int    `json:"mtu"`
	Ip6                   string `json:"Ip6"`
	PrefixLength          int    `json:"PrefixLength"`
	Gateway6              string `json:"Gateway6"`
	AddressMode           string `json:"AddressMode"`
	Name                  string
	IsDefault             bool
}

// ByAge implements sort.Interface for []Person based on
// the Age field.
type NicArray []NicInfo

func (n NicArray) Len() int           { return len(n) }
func (n NicArray) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }
func (n NicArray) Less(i, j int) bool { return n[i].Name < n[j].Name }

var BootstrapInfo map[string]interface{} = make(map[string]interface{})

var VYOS_UT_LOG_FOLDER = fmt.Sprintf("%s/vyos_ut/testLog/", GetUserHomePath())
var bootstrapInfoPath = filepath.Join(GetZvrRootPath(), BOOTSTRAP_INFO_FILE)
var haDefaultRouteScript = filepath.Join(GetZvrRootPath(), HA_DEFAULT_ROUTE_SCRIPT)

func MakeIfaceAlias(nic *NicInfo) string {
	result := ""
	if nic.L2Type != "" {
		result += fmt.Sprintf("l2type:%s;", nic.L2Type)
	}
	if nic.Category != "" {
		result += fmt.Sprintf("category:%s;", nic.Category)
	}
	if nic.PhysicalInterface != "" {
		result += fmt.Sprintf("physicalInterface:%s;", nic.PhysicalInterface)
	}
	result += fmt.Sprintf("vni:%d;", nic.Vni)
	return result
}

func GetSshPortFromBootInfo() float64 {
	port, ok := BootstrapInfo["sshPort"].(float64)
	if !ok {
		return DEFAULT_SSH_PORT
	}

	return port
}

func GetSshKey() string {
	if sshkey, ok := BootstrapInfo["publicKey"]; ok {
		return sshkey.(string)
	}

	return ""
}

func GetAdditionalNic() []interface{} {
	if additionalNics, ok := BootstrapInfo["additionalNics"]; ok {
		return additionalNics.([]interface{})
	}

	return nil
}

func GetMgmtInfoFromBootInfo() map[string]interface{} {
	mgmtNic := BootstrapInfo["managementNic"].(map[string]interface{})
	return mgmtNic
}

func IsSkipVyosIptables() bool {
	SkipVyosIptables, ok := BootstrapInfo["SkipVyosIptables"].(bool)
	if !ok {
		return false
	}

	return SkipVyosIptables
}

func SetSkipVyosIptables(enable bool) {
	if enable {
		BootstrapInfo["SkipVyosIptables"] = true
	} else {
		BootstrapInfo["SkipVyosIptables"] = false
	}
}

func SetSkipVyosIptablesForUT(enable bool) {
	if enable {
		BootstrapInfo["SkipVyosIptables"] = true
	} else {
		BootstrapInfo["SkipVyosIptables"] = false
	}
}

func IsConfigTcForVipQos() bool {
	ConfigTcForVipQos, ok := BootstrapInfo["ConfigTcForVipQos"].(bool)
	if !ok {
		/* for upgraded vpc, there is no ConfigTcForVipQos in bootstrapinfo before it reboot */
		return true
	}

	return ConfigTcForVipQos
}

func InitBootStrapInfo() {
	content, err := ioutil.ReadFile(bootstrapInfoPath)
	PanicOnError(err)
	if len(content) == 0 {
		log.Debugf("no content in %s, can not get mgmt gateway", bootstrapInfoPath)
	}

	if err := json.Unmarshal(content, &BootstrapInfo); err != nil {
		log.Debugf("can not parse info from %s, can not get mgmt gateway", bootstrapInfoPath)
	}

	if !IsEnableVyosCmd() {
		SetSkipVyosIptables(true)
	}
}

func IsHaEnabled() bool {
	if _, ok := BootstrapInfo["haStatus"]; ok {
		if !strings.EqualFold(BootstrapInfo["haStatus"].(string), NOHA) {
			return true
		}
	}

	return false
}

func GetVirtualRouterUuid() string {
	if _, ok := BootstrapInfo["uuid"]; ok {
		return BootstrapInfo["uuid"].(string)
	}

	return ""
}

func IsInManagementCidr(vipStr string) bool {
	mgmtNic := BootstrapInfo["managementNic"].(map[string]interface{})
	ipStr, _ := mgmtNic["ip"].(string)
	netmaskStr, _ := mgmtNic["netmask"].(string)

	ip := net.ParseIP(ipStr)
	netmask := net.IPMask(net.ParseIP(netmaskStr).To4())

	cidr := net.IPNet{IP: ip, Mask: netmask}

	vip := net.ParseIP(vipStr)
	return cidr.Contains(vip)
}

func GetMnNodeIps() map[string]string {
	mnNodeIps := make(map[string]string)
	mnNodeIp := BootstrapInfo["managementNodeIp"]
	if mnNodeIp != nil {
		mnNodeIpStr := mnNodeIp.(string)
		mnNodeIps[mnNodeIpStr] = mnNodeIpStr
	}

	mnPeerNodeIp := BootstrapInfo["managementPeerNodeIp"]
	if mnPeerNodeIp != nil {
		mnPeerNodeStr := mnPeerNodeIp.(string)
		mnNodeIps[mnPeerNodeStr] = mnPeerNodeStr
	}

	return mnNodeIps
}

func WriteDefaultHaScript(defaultNic *Nic) {
	defaultNicName, err := GetNicNameByMac(defaultNic.Mac)
	PanicOnError(err)
	conent := ""
	if defaultNic.Gateway != "" {
		conent += fmt.Sprintln(fmt.Sprintf("ip route add default via %s dev %s || true", defaultNic.Gateway, defaultNicName))
	}

	if defaultNic.Gateway6 != "" {
		conent += fmt.Sprintln(fmt.Sprintf("ip -6 route add default via %s dev %s || true", defaultNic.Gateway6, defaultNicName))
	}

	err = ioutil.WriteFile(haDefaultRouteScript, []byte(conent), 0755)
	PanicOnError(err)
}

func IsSLB() bool {
	applianceType, found := BootstrapInfo["applianceVmSubType"]
	if !found {
		return false
	}
	return applianceType.(string) == APPLIANCETYPE_SLB
}

func GetBootStrapNicInfo() map[string]Nic {
	bootstrapNics := make(map[string]Nic)
	mgmtNic := BootstrapInfo["managementNic"].(map[string]interface{})
	if mgmtNic != nil {
		name, ok1 := mgmtNic["deviceName"].(string)
		mac, ok2 := mgmtNic["mac"].(string)
		ip, ok3 := mgmtNic["ip"].(string)
		if ok1 && ok2 && ok3 {
			mnic := Nic{Name: name, Mac: mac, Ip: ip}
			mnic.Catatory, _ = mgmtNic["category"].(string)
			bootstrapNics[mnic.Name] = mnic
		}
	}

	otherNics := BootstrapInfo["additionalNics"].([]interface{})
	if otherNics != nil {
		for _, o := range otherNics {
			onic := o.(map[string]interface{})
			name, ok1 := onic["deviceName"].(string)
			mac, ok2 := onic["mac"].(string)
			ip, ok3 := onic["ip"].(string)
			ip6, ok4 := onic["ip6"].(string)
			if ok1 && ok2 && (ok3||ok4) {
				additionalNic := Nic{Name: name, Mac: mac, Ip: ip, Ip6: ip6}
				additionalNic.Catatory, _ = onic["category"].(string)
				bootstrapNics[additionalNic.Name] = additionalNic
			}
		}
	}

	return bootstrapNics
}

func SetHaStatus(status string) {
	BootstrapInfo["haStatus"] = status
}

func GetHaStatus() (status string) {
	haStatus := NOHA
	if v, ok := BootstrapInfo["haStatus"]; ok {
		haStatus = v.(string)
	}

	return haStatus
}

func IsRuingUT() bool {
	return strings.Contains(os.Args[0], fmt.Sprintf("%s/vyos_ut/zstack-vyos/", GetUserHomePath()))
}

func IsEnableVyosCmd() bool {
	enableVyosCmd := true
	if v, ok := BootstrapInfo["EnableVyosCmd"]; ok {
		enableVyosCmd = v.(bool)
	}

	return enableVyosCmd
}
