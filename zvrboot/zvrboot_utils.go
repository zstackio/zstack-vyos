package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"zstack-vyos/utils"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	nicsMap map[string]*utils.NicInfo = make(map[string]*utils.NicInfo)
	mgmtNic *utils.NicInfo            = &utils.NicInfo{}
)

func renameNic() {
	log.Debugf("[configure: rename nics]")
	type deviceName struct {
		expected string
		actual   string
		swap     string
	}
	devNames := make([]*deviceName, 0)

	for _, nic := range nicsMap {
		nicname, err := utils.GetNicNameByMac(nic.Mac)
		utils.PanicOnError(err)
		if nicname != nic.Name {
			devNames = append(devNames, &deviceName{
				expected: nic.Name,
				actual:   nicname,
			})
		}
	}
	if len(devNames) == 0 {
		return
	}

	for i, devname := range devNames {
		devnum := 1000 + i
		devname.swap = fmt.Sprintf("eth%v", devnum)

		err := utils.IpLinkSetDown(devname.actual)
		utils.Assertf(err == nil, "IpLinkSetDown[%s] error: %s", devname.actual, err)
		err = utils.IpLinkSetName(devname.actual, devname.swap)
		utils.Assertf(err == nil, "IpLinkSetName[%s, %s] error: %s", devname.actual, devname.swap, err)
	}

	for _, devname := range devNames {
		err := utils.IpLinkSetName(devname.swap, devname.expected)
		utils.Assertf(err == nil, "IpLinkSetName[%s, %s] error: %s", devname.swap, devname.expected, err)
		err = utils.IpLinkSetUp(devname.expected)
		utils.Assertf(err == nil, "IpLinkSetUp[%s] error: %s", devname.actual, err)
	}
}

func parseNicInfo(targetNic map[string]interface{}) *utils.NicInfo {
	var ok bool
	nicInfo := &utils.NicInfo{}

	nicInfo.Name, ok = targetNic["deviceName"].(string)
	utils.PanicIfError(ok, fmt.Errorf("cannot find 'deviceName' field for the nic"))

	nicInfo.Mac, ok = targetNic["mac"].(string)
	utils.PanicIfError(ok, errors.New("cannot find 'mac' field for the nic"))

	ip, ok := targetNic["ip"].(string)
	ip6, ok6 := targetNic["ip6"].(string)
	utils.PanicIfError(ok || ok6, fmt.Errorf("cannot find 'ip' field for the nic[name:%s]", nicInfo.Name))

	if ip != "" {
		nicInfo.Ip = ip
		nicInfo.Netmask, ok = targetNic["netmask"].(string)
		utils.PanicIfError(ok, fmt.Errorf("cannot find 'netmask' field for the nic[name:%s]", nicInfo.Name))
		nicInfo.Gateway = targetNic["gateway"].(string)

	}
	if ip6 != "" {
		nicInfo.Ip6 = ip6
		prefixLength, ok := targetNic["prefixLength"].(float64)
		utils.PanicIfError(ok, fmt.Errorf("cannot find 'prefixLength' field for the nic[name:%s]", nicInfo.Name))
		nicInfo.PrefixLength = int(prefixLength)
		nicInfo.Gateway6 = targetNic["gateway6"].(string)
		nicInfo.AddressMode, ok = targetNic["addressMode"].(string)
		utils.PanicIfError(ok, fmt.Errorf("cannot find 'addressMode' field for the nic[name:%s]", nicInfo.Name))
	}

	nicInfo.IsDefault = targetNic["isDefaultRoute"].(bool)
	if mtuFloat, ok := targetNic["mtu"].(float64); ok {
		nicInfo.Mtu = int(mtuFloat)
	}
	if targetNic["l2type"] != nil {
		nicInfo.L2Type = targetNic["l2type"].(string)
		nicInfo.Category = targetNic["category"].(string)
	}
	if targetNic["vni"] != nil {
		nicInfo.Vni = int(targetNic["vni"].(float64))
	}
	if targetNic["physicalInterface"] != nil {
		nicInfo.PhysicalInterface = targetNic["physicalInterface"].(string)
	}

	return nicInfo
}

func configureSshServer() {
	log.Debugf("[configure: SSH Server and publicKey]")
	sshkey := utils.BootstrapInfo["publicKey"].(string)
	utils.Assert(sshkey != "", "cannot find 'publicKey' in bootstrap info")
	sshport := utils.BootstrapInfo["sshPort"].(float64)
	address := mgmtNic.Ip
	utils.Assert(address != "", "cannot find eth0 ip address in bootstrap info")

	sshInfo := utils.NewSshServer().SetListen(address).SetPorts(int(sshport)).SetKeys(sshkey)
	err := sshInfo.ConfigService()
	utils.Assertf(err == nil, "configure SSH Server error: %s", err)
}

func configureRadvdServer() {
	log.Debugf("[configure: radvd service]")
	radvdMap := make(utils.RadvdAttrsMap)
	if utils.IsSLB() {
		_ = radvdMap.StopService()
		log.Debugf("skip configure radvd service with SLB")
	} else {
		for _, nic := range nicsMap {
			if nic.Ip6 != "" && nic.PrefixLength > 0 && nic.Category == "Private" {
				radvdAttr := utils.NewRadvdAttrs().SetNicName(nic.Name).SetIp6(nic.Ip6, nic.PrefixLength).SetMode(nic.AddressMode)
				radvdMap[nic.Name] = radvdAttr
			}
		}

		if err := radvdMap.ConfigService(); err != nil {
			log.Debugf("configure radvd service error: %+v", err)
		}
	}
}

func configurePassword() {
	log.Debugf("[configure: vyos password]")
	password, found := utils.BootstrapInfo["vyosPassword"]
	log.Debugf("[configure: %s", password)
	utils.Assert(found && password != "", "vyosPassword cannot be empty")
	if !isOnVMwareHypervisor() {
		log.Debugf("not vmware")
		err := utils.SetUserPasswd(utils.GetZvrUser(), fmt.Sprintf("%s", password))
		utils.Assertf(err == nil, "configure vpc password error: %s", err)

	}
}

func configureTimeZone() {
	log.Debugf("[configure: system configuration]")
	if err := utils.SetTimeZone("Asia/Shanghai"); err != nil {
		log.Debugf("configure time zone error: %+v", err)
	}
}

func configureSshMonitor() {
	if utils.IsEuler2203() {
		/* use systemd to restart sshd */
		return
	}
	
	log.Debugf("[configure: create sshd monitor]")
	cronJobMap := make(utils.CronjobMap)
	newJob := utils.NewCronjob().SetId(1).SetCommand(utils.GetCronjobFileSsh()).SetMinute("*/1")
	cronJobMap[1] = newJob
	err := cronJobMap.ConfigService()
	utils.Assertf(err == nil, "configure ssh monitor error: %s", err)
}

func configureNicInfo(nic *utils.NicInfo) {
	var err error
	// TODO ....
	//setNicTree.SetNicSmpAffinity(nic.name, "auto")

	//set kernel arguments for specific nic
	err = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/keep_addr_on_down", nic.Name), []byte("1"), 0644)
	if err != nil {
		log.Warningf("enable nic %s keep_addr_on_down failed: %s!", nic.Name, err)
	}

	err = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", nic.Name), []byte("0"), 0644)
	if err != nil {
		log.Warningf("disable nic %s accept_dad failed: %s!", nic.Name, err)
	}

	utils.SetNicOption(nic.Name)
	err = utils.IpLinkSetUp(nic.Name)
	utils.Assertf(err == nil, "IpLinkSetUp[%s] error: %s", nic.Name, err)
	if nic.Ip != "" {
		log.Debugf("[flush-nic]")
		err := utils.Ip4AddrFlush(nic.Name)
		utils.Assertf(err == nil, "IpAddr4Flush[%s] error: %+v", nic.Name, err)
		log.Debugf("[flush-route]")
		err = utils.FlushNicRoute(nic.Name)
		utils.Assertf(err == nil, "Flush nic[%s] route error: %+v", nic.Name, err)
		log.Debugf("[getcidr]")
		cidr, err := utils.NetmaskToCIDR(nic.Netmask)
		utils.PanicOnError(err)
		ipString := fmt.Sprintf("%v/%v", nic.Ip, cidr)
		log.Debugf("[addip]")
		log.Debugf("nic [%s] add ipv4 address %s", nic.Name, ipString)
		err = utils.IpAddrAdd(nic.Name, ipString)
		utils.Assertf(err == nil, "IpAddrAdd[%s, %s] error: %+v", nic.Name, ipString, err)
	}
	if nic.Ip6 != "" {
		err := utils.Ip6AddrFlush(nic.Name)
		utils.Assertf(err == nil, "IpAddr6Flush[%s] error: %+v", nic.Name, err)
		ip6String := fmt.Sprintf("%s/%d", nic.Ip6, nic.PrefixLength)
		log.Debugf("nic [%s] add ipv6 address %s", nic.Name, ip6String)
		err = utils.IpAddrAdd(nic.Name, ip6String)
		utils.Assertf(err == nil, "IpAddrAdd[%s, %s] error: %+v", nic.Name, ip6String, err)
	}
	if nic.Mtu != 0 {
		if err := utils.IpLinkSetMTU(nic.Name, nic.Mtu); err != nil {
			log.Debugf("IpLinkSetMTU[%s, %d] error: %+v", nic.Name, nic.Mtu, err)
		}
	}
	if nic.IsDefault {
		if nic.Gateway != "" {
			routeEntry := utils.NewIpRoute().SetGW(nic.Gateway).SetDev(nic.Name).SetTable(utils.RT_TABLES_MAIN).SetProto(utils.RT_PROTOS_STATIC)
			err := utils.IpRouteAdd(routeEntry)
			utils.Assertf(err == nil, "IpRouteAdd[%+v] error: %+v", routeEntry, err)
		}
		if nic.Gateway6 != "" {
			route6Entry := utils.NewIpRoute().SetGW(nic.Gateway).SetDev(nic.Name).SetTable(utils.RT_TABLES_MAIN).SetProto(utils.RT_PROTOS_STATIC)
			err := utils.IpRouteAdd(route6Entry)
			utils.Assertf(err == nil, "IpRouteAdd[%+v] error: %+v", route6Entry, err)
		}
	}
	if nic.L2Type != "" {
		err := utils.IpLinkSetAlias(nic.Name, utils.MakeIfaceAlias(nic))
		utils.Assertf(err == nil, "IpLinkSetAlias[%s] error: %+v", nic.Name, err)
	}
	if utils.GetHaStatus() != utils.NOHA && nic.Name != "eth0" && !utils.IsSLB() {
		err := utils.IpLinkSetDown(nic.Name)
		utils.Assertf(err == nil, "IpLinkSetDown[%s] error: %+v", nic.Name, err)
	}
	if nic.Name == "eth0" {
		mgmtNodeCidr := utils.BootstrapInfo["managementNodeCidr"]
		if mgmtNodeCidr != nil {
			mgmtNodeCidrStr := mgmtNodeCidr.(string)
			nexthop, _ := utils.IpRouteGet(mgmtNodeCidrStr)
			if nexthop != nic.Gateway {
				defaultRoute := utils.NewIpRoute().SetDst(mgmtNodeCidrStr).SetGW(nic.Gateway)
				if err = utils.IpRouteAdd(defaultRoute); err != nil {
					log.Debugf("IpRouteAdd route entry[Dst:%s gateway:%s] error: %+v", mgmtNodeCidrStr, nic.Gateway, err)
				}
				utils.AddRoute(mgmtNodeCidrStr, nic.Gateway)
			}
		}
	}

	if nic.Category == "Private" {
		err = utils.InitNicFirewall(nic.Name, nic.Ip, false, utils.IPTABLES_ACTION_REJECT)
	} else {
		err = utils.InitNicFirewall(nic.Name, nic.Ip, true, utils.IPTABLES_ACTION_REJECT)
	}
	if err != nil {
		log.Debugf("InitNicFirewall for nic: %s failed", err.Error())
	}

}

func configureMgmtNic() {
	log.Debugf("[configure: interfaces[%s] ... ", mgmtNic.Name)
	
	configureNicInfo(mgmtNic)
}

func configureAdditionNic() {
	for name, nic := range nicsMap {
		if name != mgmtNic.Name {
			log.Debugf("[configure: interfaces[%s] ... ", name)
			configureNicInfo(nic)
		}
	}
}

func parseNicFromBootstrap() {
	log.Debugf("[configure: parse managenent nic info]")
	nicInfo := utils.BootstrapInfo["managementNic"].(map[string]interface{})
	if nicInfo == nil {
		panic(errors.New("no field 'managementNic' in bootstrap info"))
	}
	mgmtNic = parseNicInfo(nicInfo)
	nicsMap[mgmtNic.Name] = mgmtNic

	log.Debugf("[configure: parse additional nic info]")
	otherNics := utils.BootstrapInfo["additionalNics"].([]interface{})
	if otherNics != nil {
		for _, o := range otherNics {
			onic := o.(map[string]interface{})
			n := parseNicInfo(onic)
			nicsMap[n.Name] = n
		}
	}
}

func printBootStrapInfo() {
	SkipVyosIptables := utils.IsSkipVyosIptables()
	utils.Assert(SkipVyosIptables == true, "disable vyos cli has been set, but SkipVyosIptables is disable")
	applianceTypeTmp, found := utils.BootstrapInfo["applianceVmSubType"]
	if !found {
		applianceTypeTmp = "None"
	}
	applianceType := applianceTypeTmp.(string)

	log.Debugf("bootstrapInfo: %+v", utils.BootstrapInfo)
	log.Debugf("EnableVyosCli: %+v", utils.IsEnableVyosCmd())
	log.Debugf("SkipVyosIptables: %+v", SkipVyosIptables)
	log.Debugf("applianceType: %+v", applianceType)
}

func checkNicAddress() {
	log.Debugf("[configure: check nic's ip address]")
	haStatus := utils.NOHA
	if v, ok := utils.BootstrapInfo["haStatus"]; ok {
		haStatus = v.(string)
	}

	if strings.EqualFold(haStatus, utils.NOHA) {
		dupinfo := ""
		for _, nic := range nicsMap {
			if nic.Ip != "" && utils.CheckIpDuplicate(nic.Name, nic.Ip) {
				dupinfo = fmt.Sprintf("%s duplicate ip %s in nic %s\n", dupinfo, nic.Ip, nic.Mac)
			}
		}
		if !strings.EqualFold(dupinfo, "") {
			log.Error(dupinfo)
			err := utils.MkdirForFile(getNetworkHealthStatusPath(), 0755)
			utils.PanicOnError(err)
			err = ioutil.WriteFile(getNetworkHealthStatusPath(), []byte(dupinfo), 0755)
			utils.PanicOnError(err)
		}
	}

	for _, nic := range nicsMap {
		utils.Arping(nic.Name, nic.Ip, nic.Gateway)
	}
}

func configureHaScript() {
	log.Debugf("[configure: write default Ha script]")
	for _, nic := range nicsMap {
		if nic.IsDefault {
			defaultNic := utils.Nic{Name: nic.Name, Mac: nic.Mac, Ip: nic.Ip, Ip6: nic.Ip6,
				Gateway: nic.Gateway, Gateway6: nic.Gateway6}

			utils.WriteDefaultHaScript(&defaultNic)
		}
	}
}

func configureSystem() {
	if utils.IsVYOS() {
		resetVyos()
	}
	printBootStrapInfo()
	configureTimeZone()
	parseNicFromBootstrap()
	renameNic()
	configureMgmtNic()
	configurePassword()
	configureSshServer()
	configureAdditionNic()
	configureRadvdServer()
	configureSshMonitor()
	checkNicAddress()
	configureHaScript()
}
