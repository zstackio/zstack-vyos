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
    BOOTSTRAP_INFO_UT = "/home/vyos/vyos_ut/zstack-vyos/bootstrapinfo"
)

var MgtNicForUT NicInfo
var PubNicForUT NicInfo
var PrivateNicsForUT []NicInfo
var AdditionalPubNicsForUT []NicInfo
var reservedIpForMgt []string
var reservedIpForPubL3 []string
var freeIpsForMgt []string
var freeIpsForPubL3 []string

func init() {
    if !IsRuingUT() {
        return
    }
    
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
    
    if err := json.Unmarshal(content, &BootstrapInfo); err != nil {
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
    
    netmask, ok := m["netmask"].(string)
    if !ok {
        tempNic.Netmask = ""
    } else {
        tempNic.Netmask = netmask
    }
    
    gateway, ok := m["gateway"].(string)
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
    
    prefixLength, ok := m["prefixLength"].(float64)
    if !ok {
        tempNic.PrefixLength = 0
    } else {
        tempNic.PrefixLength = int(prefixLength)
    }
    
    gateway6, ok := m["gateway6"].(string)
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
    
    category, ok := m["category"].(string)
    if !ok {
        return fmt.Errorf("there is no nic category for %+v", m)
    }
    tempNic.Category = category
    
    l2Type, ok := m["l2type"].(string)
    if !ok {
        tempNic.L2Type = ""
    } else {
        tempNic.L2Type = l2Type
    }
    
    physicalInterface, ok := m["physicalInterface"].(string)
    if !ok {
        tempNic.PhysicalInterface = ""
    } else {
        tempNic.PhysicalInterface = physicalInterface
    }
    
    vni, ok := m["vni"].(int)
    if !ok {
        tempNic.Vni = 0
    } else {
        tempNic.Vni = vni
    }
    
    mtu, ok := m["mtu"].(int)
    if !ok {
        tempNic.Mtu = 1450
    } else {
        tempNic.Mtu = mtu
    }
    
    addressMode, ok := m["addressMode"].(string)
    if !ok {
        tempNic.AddressMode = "Stateful-DHCP"
    } else {
        tempNic.AddressMode = addressMode
    }
    
    tempNic.FirewallDefaultAction = "reject"
    
    return nil
}

func ParseBootStrapNicInfo() {
    nicString := BootstrapInfo["managementNic"].(map[string]interface{})
    if nicString != nil {
        if err := getNic(nicString, &MgtNicForUT); err != nil {
            return
        }
    }
    
    otherNics := BootstrapInfo["additionalNics"].([]interface{})
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
    lastIp := rand.Int() & 0x3F + 10
    if lastIp == num  {
        lastIp = rand.Int() & 0xFF + 10
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
    return BootstrapInfo["mgtGateway"].(string)
}
