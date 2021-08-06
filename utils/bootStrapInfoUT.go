package utils

import (
    "encoding/json"
    "fmt"
    log "github.com/Sirupsen/logrus"
    "io/ioutil"
    "sort"
    "strconv"
    "strings"
    "math/rand"
    "time"
)

const (
    VYOS_UT_LOG_FOLDER="/home/vyos/vyos_ut/testLog/"
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

var MgtNicForUT NicInfo
var PubNicForUT NicInfo
var PrivateNicsForUT []NicInfo
var AdditionalPubNicsForUT []NicInfo
var reservedIpForMgt []string
var reservedIpForPubL3 []string
var freeIpsForMgt []string
var freeIpsForPubL3 []string

func InitForUt() {
    InitBootStrapInfoForUT()
    ParseBootStrapNicInfo()
    rand.Seed(time.Now().UnixNano())
    for _, ip := range reservedIpForMgt {
        freeIpsForMgt = append(freeIpsForMgt, ip)
    }
    
    for _, ip := range reservedIpForPubL3 {
        freeIpsForPubL3 = append(freeIpsForPubL3, ip)
    }
}

func InitBootStrapInfoForUT() {
    log.Debugf("start init boot strap for ut")
    content, err := ioutil.ReadFile(BOOTSTRAP_INFO_UT)
    if err != nil {
        return
    }
    if len(content) == 0 {
        log.Debugf("no content in %s, can not get mgmt gateway", BOOTSTRAP_INFO_CACHE)
    }
    
    if err := json.Unmarshal(content, &bootstrapInfo); err != nil {
        log.Debugf("can not parse info from %s, can not get mgmt gateway", BOOTSTRAP_INFO_CACHE)
    }
}

func getNic(m map[string]interface{}, tempNic *NicInfo) error  {
    name, ok := m["deviceName"].(string)
    if !ok {
        return fmt.Errorf("there is no nic name for %+v", m)
    }
    tempNic.Name = name
    
    mac, ok := m["mac"].(string)
    if !ok {
        return fmt.Errorf("there is no nic mac for %+v", m)
    }
    tempNic.Mac = mac
    
    ip, ok := m["ip"].(string)
    if !ok {
        tempNic.Ip = ""
    } else {
        tempNic.Ip = ip
    }
    
    netmask, _ := m["netmask"].(string)
    if !ok {
        tempNic.Netmask = ""
    } else {
        tempNic.Netmask = netmask
    }
    
    gateway, _ := m["gateway"].(string)
    if !ok {
        tempNic.Gateway = ""
    } else {
        tempNic.Gateway = gateway
    }
    
    ip6, ok := m["ip6"].(string)
    if !ok {
        tempNic.Ip6 = ""
    } else {
        tempNic.Ip6 = ip6
    }
    
    prefixLength, _ := m["prefixLength"].(float64)
    if !ok {
        tempNic.PrefixLength = 0
    } else {
        tempNic.PrefixLength = int(prefixLength)
    }
    
    gateway6, _ := m["gateway6"].(string)
    if !ok {
        tempNic.Gateway6 = ""
    } else {
        tempNic.Gateway6 = gateway6
    }
    
    isDefault, ok := m["isDefaultRoute"].(bool)
    if !ok {
        tempNic.IsDefault = false
    } else {
        tempNic.IsDefault = isDefault
    }
    
    category, _ := m["category"].(string)
    if !ok {
        return fmt.Errorf("there is no nic category for %+v", m)
    }
    tempNic.Category = category
    
    l2Type, _ := m["L2Type"].(string)
    if !ok {
        tempNic.L2Type = ""
    } else {
        tempNic.L2Type = l2Type
    }
    
    physicalInterface, _ := m["physicalInterface"].(string)
    if !ok {
        tempNic.PhysicalInterface = ""
    } else {
        tempNic.PhysicalInterface = physicalInterface
    }
    
    vni, _ := m["vni"].(int)
    if !ok {
        tempNic.Vni = 0
    } else {
        tempNic.Vni = vni
    }
    
    mtu, _ := m["mtu"].(int)
    if !ok {
        tempNic.Mtu = 1450
    } else {
        tempNic.Mtu = mtu
    }
    
    addressMode, _ := m["addressMode"].(string)
    if !ok {
        tempNic.AddressMode = "Stateful-DHCP"
    } else {
        tempNic.AddressMode = addressMode
    }
    
    tempNic.FirewallDefaultAction = "reject"
    
    return nil
}

func ParseBootStrapNicInfo() {
    nicString := bootstrapInfo["managementNic"].(map[string]interface{})
    if nicString != nil {
        if err := getNic(nicString, &MgtNicForUT); err != nil {
            return
        }
    }
    
    otherNics := bootstrapInfo["additionalNics"].([]interface{})
    if otherNics != nil {
        for _, o := range otherNics {
            onic := o.(map[string]interface{})
            var additionalNic NicInfo
            if err := getNic(onic, &additionalNic); err != nil {
                return
            }
            
            if additionalNic.IsDefault {
                PubNicForUT = additionalNic
                continue
            }
            
            if additionalNic.Category == NIC_TYPE_PRIVATE {
                PrivateNicsForUT = append(PrivateNicsForUT, additionalNic)
            } else {
                AdditionalPubNicsForUT = append(AdditionalPubNicsForUT, additionalNic)
            }
        }
    }
    
    sort.Sort(NicArray(PrivateNicsForUT))
    sort.Sort(NicArray(AdditionalPubNicsForUT))
    
    ips := bootstrapInfo["reservedIpForMgt"].([]interface{})
    for _, ip := range ips {
        reservedIpForMgt = append(reservedIpForMgt, ip.(string))
    }
    
    ips = bootstrapInfo["reservedIpForPubL3"].([]interface{})
    for _, ip := range ips {
        reservedIpForPubL3 = append(reservedIpForPubL3, ip.(string))
    }
    return
}

func SetHaStatus(status string) {
    bootstrapInfo["haStatus"] = status
}

func GetHaStatus() (status string) {
    return bootstrapInfo["haStatus"].(string)
}

func GetRandomIpForSubnet(sourceIp string) string {
    sips := strings.Split(sourceIp, ".")
    num, _ := strconv.Atoi(sips[0])
    /* normal case, gateway will be the first or last ip address */
    lastIp := rand.Int() & 0x3F + 10
    if lastIp == num  {
        lastIp = rand.Int() & 0xFF
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
    
    ip := freeIpsForMgt[len(freeIpsForMgt) - 1]
    freeIpsForMgt = freeIpsForMgt[:len(freeIpsForMgt) - 1]
    return ip, nil
}

func ReleaseMgtIp(ip string)  {
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
    
    ip := freeIpsForPubL3[len(freeIpsForPubL3) - 1]
    freeIpsForPubL3 = freeIpsForPubL3[:len(freeIpsForPubL3) - 1]
    return ip, nil
}

func ReleasePubL3Ip(ip string)  {
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
    return bootstrapInfo["mgtGateway"].(string)
}
