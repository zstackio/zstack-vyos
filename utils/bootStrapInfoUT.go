package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func GetBootstrapInfoUt() string {
	return filepath.Join(GetUserHomePath(), "vyos_ut/zstack-vyos/bootstrapinfo")
}

func getIptablesRuleFileUt() string {
	return filepath.Join(GetUserHomePath(), "vyos_ut/zstack-vyos/iptables.rules")
}

func getBootConigFile() string {
	return filepath.Join(GetUserHomePath(), "vyos_ut/zstack-vyos/test/boot_config.sh")
}

var (
	MgtNicForUT            NicInfo
	PubNicForUT            NicInfo
	PrivateNicsForUT       []NicInfo
	AdditionalPubNicsForUT []NicInfo
	reservedIpForMgt       []string
	reservedIpForPubL3     []string
	freeIpsForMgt          []string
	freeIpsForPubL3        []string
)

func init() {
	if !IsRuingUT() {
		return
	}

	InitBootStrapInfoForUT()
	ParseBootStrapNicInfo()
	ReserveIpForUT()
	rand.Seed(time.Now().UnixNano())
}

func ReserveIpForUT() {
	for _, ip := range reservedIpForMgt {
		freeIpsForMgt = append(freeIpsForMgt, ip)
	}

	for _, ip := range reservedIpForPubL3 {
		freeIpsForPubL3 = append(freeIpsForPubL3, ip)
	}
}

func CleanTestEnvForUT() {
	b := Bash{
		Command: fmt.Sprintf("sg vyattacfg -c '/bin/vbash %s'", getBootConigFile()),
		Sudo:    true,
	}
	if ret, _, _, err := b.RunWithReturn(); ret != 0 || err != nil {
		log.Debugf("clean vyos commit err, ret: %d, err : %+v", ret, err)
	}

	ifaces, err := net.Interfaces()
	PanicOnError(err)
	for _, iface := range ifaces {
		if iface.Name == "eth0" || iface.Name == "lo" {
			continue
		}
		if strings.HasPrefix(iface.Name, "ifb") {
			IpLinkDel(iface.Name)
			continue
		}
		IpAddrFlush(iface.Name)
		IpLinkSetAlias(iface.Name, "")
	}

	file_lists := []string{GetZtackConfigPath(), CROND_CONFIG_FILE}
	for _, f := range file_lists {
		if ok, err := PathExists(f); ok || err != nil {
			log.Debugf("cleanUpConfigDir: file [%s] will be delete", f)
			if err := DeleteAllFiles(f); err != nil {
				log.Debugf("cleanUpConfigDir: delete file [%s] error: %+v", f, err)
			}
		}
	}

	BootstrapInfo = make(map[string]interface{})

	InitBootStrapInfoForUT()
	ParseBootStrapNicInfo()
	ReserveIpForUT()
	restoreConfigure()
}

func restoreConfigure() {
	bash := Bash{
		Command: fmt.Sprintf("iptables-restore -w < %s", getIptablesRuleFileUt()),
		Sudo:    true,
	}
	bash.Run()
}

func InitBootStrapInfoForUT() {
	log.Debugf("start init boot strap for ut")
	content, err := ioutil.ReadFile(GetBootstrapInfoUt())
	if err != nil {
		return
	}
	if len(content) == 0 {
		log.Debugf("no content in %s, can not get mgmt gateway", GetBootstrapInfoUt())
	}

	if err := json.Unmarshal(content, &BootstrapInfo); err != nil {
		log.Debugf("can not parse info from %s, can not get mgmt gateway", GetBootstrapInfoUt())
	}
}

func parseNicForUT(m map[string]interface{}) (NicInfo, error) {
	nicInfo := NicInfo{}
	name, ok := m["deviceName"].(string)
	if !ok {
		return nicInfo, fmt.Errorf("there is no nic name for %+v", m)
	}
	nicInfo.Name = name

	mac, ok := m["mac"].(string)
	if !ok {
		return nicInfo, fmt.Errorf("there is no nic mac for %+v", m)
	}
	nicInfo.Mac = mac

	ip, ok := m["ip"].(string)
	if !ok {
		nicInfo.Ip = ""
	} else {
		nicInfo.Ip = ip
	}

	netmask, ok := m["netmask"].(string)
	if !ok {
		nicInfo.Netmask = ""
	} else {
		nicInfo.Netmask = netmask
	}

	gateway, ok := m["gateway"].(string)
	if !ok {
		nicInfo.Gateway = ""
	} else {
		nicInfo.Gateway = gateway
	}

	ip6, ok := m["ip6"].(string)
	if !ok {
		nicInfo.Ip6 = ""
	} else {
		nicInfo.Ip6 = ip6
	}

	prefixLength, ok := m["prefixLength"].(float64)
	if !ok {
		nicInfo.PrefixLength = 0
	} else {
		nicInfo.PrefixLength = int(prefixLength)
	}

	gateway6, ok := m["gateway6"].(string)
	if !ok {
		nicInfo.Gateway6 = ""
	} else {
		nicInfo.Gateway6 = gateway6
	}

	isDefault, ok := m["isDefaultRoute"].(bool)
	if !ok {
		nicInfo.IsDefault = false
	} else {
		nicInfo.IsDefault = isDefault
	}

	category, ok := m["category"].(string)
	if !ok {
		return nicInfo, fmt.Errorf("there is no nic category for %+v", m)
	}
	nicInfo.Category = category

	l2Type, ok := m["l2type"].(string)
	if !ok {
		nicInfo.L2Type = ""
	} else {
		nicInfo.L2Type = l2Type
	}

	physicalInterface, ok := m["physicalInterface"].(string)
	if !ok {
		nicInfo.PhysicalInterface = ""
	} else {
		nicInfo.PhysicalInterface = physicalInterface
	}

	vni, ok := m["vni"].(int)
	if !ok {
		nicInfo.Vni = 0
	} else {
		nicInfo.Vni = vni
	}

	mtu, ok := m["mtu"].(int)
	if !ok {
		nicInfo.Mtu = 1450
	} else {
		nicInfo.Mtu = mtu
	}

	addressMode, ok := m["addressMode"].(string)
	if !ok {
		nicInfo.AddressMode = "Stateful-DHCP"
	} else {
		nicInfo.AddressMode = addressMode
	}

	nicInfo.FirewallDefaultAction = "reject"

	return nicInfo, nil
}

func ParseBootStrapNicInfo() {
	PrivateNicsForUT = []NicInfo{}
	AdditionalPubNicsForUT = []NicInfo{}
	reservedIpForMgt = []string{}
	reservedIpForPubL3 = []string{}
	freeIpsForMgt = []string{}
	freeIpsForPubL3 = []string{}
	nicString := BootstrapInfo["managementNic"].(map[string]interface{})
	if nicString != nil {
		nicInfo, err := parseNicForUT(nicString)
		PanicOnError(err)
		MgtNicForUT = nicInfo
	}

	otherNics := BootstrapInfo["additionalNics"].([]interface{})
	if otherNics != nil {
		for _, o := range otherNics {
			onic := o.(map[string]interface{})
			nicInfo, err := parseNicForUT(onic)
			PanicOnError(err)

			if nicInfo.IsDefault {
				PubNicForUT = nicInfo
				continue
			}

			if nicInfo.Category == NIC_TYPE_PRIVATE {
				PrivateNicsForUT = append(PrivateNicsForUT, nicInfo)
			} else {
				AdditionalPubNicsForUT = append(AdditionalPubNicsForUT, nicInfo)
			}
		}
	}

	sort.Sort(NicArray(PrivateNicsForUT))
	sort.Sort(NicArray(AdditionalPubNicsForUT))

	ips := BootstrapInfo["reservedIpForMgt"].([]interface{})
	for _, ip := range ips {
		reservedIpForMgt = append(reservedIpForMgt, ip.(string))
	}

	ips = BootstrapInfo["reservedIpForPubL3"].([]interface{})
	for _, ip := range ips {
		reservedIpForPubL3 = append(reservedIpForPubL3, ip.(string))
	}
	return
}

func GetRandomIpForSubnet(sourceIp string) string {
	sips := strings.Split(sourceIp, ".")
	num, _ := strconv.Atoi(sips[3])
	/* normal case, gateway will be the first or last ip address */
	lastIp := rand.Int()&0x3F + 10
	if lastIp == num {
		lastIp = rand.Int()&0xFF + 10
	}

	sips[3] = fmt.Sprintf("%d", lastIp)
	return strings.Join(sips, ".")
}

func GetFreeMgtIp() (string, error) {
	if len(freeIpsForMgt) <= 0 {
		return "", fmt.Errorf("not enough mgt ip")
	}

	if len(freeIpsForMgt) == 1 {
		ip := freeIpsForMgt[0]
		freeIpsForMgt = []string{}
		return ip, nil
	}

	ip := freeIpsForMgt[len(freeIpsForMgt)-1]
	freeIpsForMgt = freeIpsForMgt[:len(freeIpsForMgt)-1]
	return ip, nil
}

func ReleaseMgtIp(ip string) {
	exist := false
	for _, ipa := range freeIpsForMgt {
		if ip == ipa {
			exist = true
			break
		}
	}

	if !exist {
		freeIpsForMgt = append(freeIpsForMgt, ip)
	}
}

func GetFreePubL3Ip() (string, error) {
	if len(freeIpsForPubL3) <= 0 {
		return "", fmt.Errorf("not enough pubL3 ip")
	}

	if len(freeIpsForPubL3) == 1 {
		ip := freeIpsForPubL3[0]
		freeIpsForPubL3 = []string{}
		return ip, nil
	}

	ip := freeIpsForPubL3[len(freeIpsForPubL3)-1]
	freeIpsForPubL3 = freeIpsForPubL3[:len(freeIpsForPubL3)-1]
	return ip, nil
}

func ReleasePubL3Ip(ip string) {
	exist := false
	for _, ipa := range freeIpsForPubL3 {
		if ip == ipa {
			exist = true
			break
		}
	}

	if !exist {
		freeIpsForPubL3 = append(freeIpsForPubL3, ip)
	}
}

func GetMgtGateway() string {
	return BootstrapInfo["mgtGateway"].(string)
}

func SetEnableVyosCmdForUT(enable bool) {
	if enable {
		BootstrapInfo["EnableVyosCmd"] = true
	} else {
		BootstrapInfo["EnableVyosCmd"] = false
	}
}
