package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	ModuleName           = "zvrboot"
	VIRTIO_PORT_PATH     = "/dev/virtio-ports/applianceVm.vport"
	BOOTSTRAP_INFO_FILE  = "bootstrap-info.json"
	TMP_LOCATION_FOR_ESX = "/tmp/bootstrap-info.json"
	// use this rule number to set a rule which confirm route entry work issue ZSTAC-6170
	ROUTE_STATE_NEW_ENABLE_FIREWALL_RULE_NUMBER = 9999
)

type nic struct {
	mac                 string
	ip                  string
	name                string
	netmask             string
	isDefaultRoute      bool
	gateway             string
	category            string
	l2type              string
	l2PhysicalInterface string
	vni                 int
	mtu                 int
	ip6                 string
	prefixLength        int
	gateway6            string
	addressMode         string
}

var bootstrapInfo map[string]interface{} = make(map[string]interface{})
var nics map[string]*nic = make(map[string]*nic)

func getBootstrapInfoPath() string {
	return filepath.Join(utils.GetZvrRootPath(), BOOTSTRAP_INFO_FILE)
}

func getNetworkHealthStatusPath() string {
	return filepath.Join(utils.GetZvrRootPath(), ".duplicate")
}

func getZvrbootLogPath() string {
	return filepath.Join(utils.GetZvrRootPath(), "zvrboot.log")
}

func waitIptablesServiceOnline() {
	bash := utils.Bash{
		Command: "sudo /sbin/iptables-save",
	}

	utils.LoopRunUntilSuccessOrTimeout(func() bool {
		err := bash.Run()
		if err != nil {
			log.Debugf("iptables service seems not ready, %v", err)
		}
		return err == nil
	}, time.Duration(120)*time.Second, time.Duration(500)*time.Millisecond)
}

func waitVirtioPortOnline() {
	utils.LoopRunUntilSuccessOrTimeout(func() bool {
		ok, err := utils.PathExists(VIRTIO_PORT_PATH)
		utils.PanicOnError(err)
		if !ok {
			log.Debugf("%s doesn't not exist, wait it ...", VIRTIO_PORT_PATH)
		}
		return ok
	}, time.Duration(120)*time.Second, time.Duration(500)*time.Millisecond)
}

func isOnVMwareHypervisor() bool {
	log.Debugf("is VMware")
	bash := utils.Bash{
		Command: "dmesg | grep -q 'Hypervisor.*VMware'",
		Sudo:    true,
	}

	if ret, _, _, err := bash.RunWithReturn(); ret == 0 && err == nil {
		return true
	}

	return false
}

func parseEsxBootInfo() {
	utils.LoopRunUntilSuccessOrTimeout(func() bool {
		if _, err := os.Stat(TMP_LOCATION_FOR_ESX); os.IsNotExist(err) {
			log.Debugf("bootstrap info not ready, waiting ...")
			return false
		}

		content, err := ioutil.ReadFile(TMP_LOCATION_FOR_ESX)
		utils.PanicOnError(err)

		if len(content) == 0 {
			return false
		}

		log.Debugf("recieved bootstrap info:\nsize:%d\n%s", len(content), string(content))
		if err = json.Unmarshal(content, &bootstrapInfo); err != nil {
			panic(errors.Wrap(err, fmt.Sprintf("unable to JSON parse:\n %s", string(content))))
		}

		err = utils.MkdirForFile(getBootstrapInfoPath(), 0666)
		utils.PanicOnError(err)
		err = ioutil.WriteFile(getBootstrapInfoPath(), content, 0777)
		utils.PanicOnError(err)
		os.Remove(TMP_LOCATION_FOR_ESX)
		return true
	}, time.Duration(300)*time.Second, time.Duration(1)*time.Second)
}

func parseKvmBootInfo() {
	utils.LoopRunUntilSuccessOrTimeout(func() bool {
		content, err := ioutil.ReadFile(VIRTIO_PORT_PATH)
		utils.PanicOnError(err)
		if len(content) == 0 {
			log.Debugf("no content in %s, it may not be ready, wait it ...", VIRTIO_PORT_PATH)
			return false
		}
		log.Debugf("recieved bootstrap info:\nsize:%d\n%s", len(content), string(content))

		if err := json.Unmarshal(content, &bootstrapInfo); err != nil {
			panic(errors.Wrap(err, fmt.Sprintf("unable to JSON parse:\n %s", string(content))))
		}
		log.Debugf("%s", utils.GetZvrRootPath())
		err = utils.MkdirForFile(getBootstrapInfoPath(), 0666)
		utils.PanicOnError(err)
		err = ioutil.WriteFile(getBootstrapInfoPath(), content, 0666)
		utils.PanicOnError(err)
		err = os.Chmod(getBootstrapInfoPath(), 0777)
		utils.PanicOnError(err)
		return true
	}, time.Duration(300)*time.Second, time.Duration(1)*time.Second)
}

func resetVyos() {
	// clear all configuration in case someone runs 'save' command manually before,
	// to keep the vyos must be stateless

	// delete all interfaces
	tree := server.NewParserFromShowConfiguration().Tree
	tree.Delete("interfaces ethernet")
	tree.Apply(true)

	/*the API RunVyosScriptAsUserVyos doesn't work for this command.
	the correct command sequence is that
	configur
	load
	commit
	save
	exit
	current for workaround ,just */
	// reload default configuration
	//server.RunVyosScriptAsUserVyos("load /opt/vyatta/etc/config.boot.default\nsave")
	cleanUpTmpDir()
	cleanUpConfigDir()
}

func cleanUpTmpDir() {
	b := utils.Bash{
		Command: "sudo rm -rf /tmp/tmp-log",
	}
	b.Run()
}

func cleanUpConfigDir() {
	file_lists := []string{utils.GetZtackConfigPath(), utils.CROND_CONFIG_FILE}
	for _, f := range file_lists {
		if ok, err := utils.PathExists(f); ok || err != nil {
			log.Debugf("cleanUpConfigDir: file [%s] will be delete", f)
			if err := utils.DeleteAllFiles(f); err != nil {
				log.Debugf("cleanUpConfigDir: delete file [%s] error: %+v", f, err)
			}
		}
	}
}

func checkIpDuplicate() {
	// duplicate ip check
	dupinfo := ""
	for _, nic := range nics {
		if nic.ip != "" && utils.CheckIpDuplicate(nic.name, nic.ip) {
			dupinfo = fmt.Sprintf("%s duplicate ip %s in nic %s\n", dupinfo, nic.ip, nic.mac)
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

func configureVyos() {
	resetVyos()
	var defaultNic utils.Nic

	mgmtNic := bootstrapInfo["managementNic"].(map[string]interface{})
	if mgmtNic == nil {
		panic(errors.New("no field 'managementNic' in bootstrap info"))
	}

	haStatus := utils.NOHA
	if v, ok := bootstrapInfo["haStatus"]; ok {
		haStatus = v.(string)
	}

	eth0 := &nic{name: "eth0"}
	var ok bool
	eth0.mac, ok = mgmtNic["mac"].(string)
	utils.PanicIfError(ok, errors.New("cannot find 'mac' field for the management nic"))
	eth0.ip, ok = mgmtNic["ip"].(string)
	ip, ok := mgmtNic["ip"].(string)
	ip6, ok6 := mgmtNic["ip6"].(string)
	utils.PanicIfError(ok || ok6, fmt.Errorf("cannot find 'ip' field for the nic[name:%s]", eth0.name))
	if ip != "" {
		eth0.ip = ip
		eth0.netmask, ok = mgmtNic["netmask"].(string)
		utils.PanicIfError(ok, fmt.Errorf("cannot find 'netmask' field for the nic[name:%s]", eth0.name))
		eth0.gateway = mgmtNic["gateway"].(string)
	}
	if ip6 != "" {
		eth0.ip6 = ip6
		prefixLength, ok := mgmtNic["prefixLength"].(float64)
		utils.PanicIfError(ok, fmt.Errorf("cannot find 'prefixLength' field for the nic[name:%s]", eth0.name))
		eth0.prefixLength = int(prefixLength)
		eth0.gateway6 = mgmtNic["gateway6"].(string)
		eth0.addressMode, ok = mgmtNic["addressMode"].(string)
		utils.PanicIfError(ok, fmt.Errorf("cannot find 'addressMode' field for the nic[name:%s]", eth0.name))
	}
	eth0.isDefaultRoute = mgmtNic["isDefaultRoute"].(bool)

	if mtuFloat, ok := mgmtNic["mtu"].(float64); ok {
		eth0.mtu = int(mtuFloat)
	}

	if mgmtNic["l2type"] != nil {
		eth0.l2type = mgmtNic["l2type"].(string)
		eth0.category = mgmtNic["category"].(string)
	}
	if mgmtNic["vni"] != nil {
		eth0.vni = int(mgmtNic["vni"].(float64))
	}
	if mgmtNic["physicalInterface"] != nil {
		eth0.l2PhysicalInterface = mgmtNic["physicalInterface"].(string)
	}
	nics[eth0.name] = eth0

	otherNics := bootstrapInfo["additionalNics"].([]interface{})
	if otherNics != nil {
		for _, o := range otherNics {
			onic := o.(map[string]interface{})
			n := &nic{}
			n.name, ok = onic["deviceName"].(string)
			utils.PanicIfError(ok, fmt.Errorf("cannot find 'deviceName' field for the nic"))
			n.mac, ok = onic["mac"].(string)
			utils.PanicIfError(ok, errors.New("cannot find 'mac' field for the nic"))
			ip, ok := onic["ip"].(string)
			ip6, ok6 := onic["ip6"].(string)
			utils.PanicIfError(ok || ok6, fmt.Errorf("cannot find 'ip' field for the nic[name:%s]", n.name))
			if ip != "" {
				n.ip = ip
				n.netmask, ok = onic["netmask"].(string)
				utils.PanicIfError(ok, fmt.Errorf("cannot find 'netmask' field for the nic[name:%s]", n.name))
				n.gateway = onic["gateway"].(string)
			}
			if ip6 != "" {
				n.ip6 = ip6
				prefixLength, ok := onic["prefixLength"].(float64)
				utils.PanicIfError(ok, fmt.Errorf("cannot find 'prefixLength' field for the nic[name:%s]", n.name))
				n.prefixLength = int(prefixLength)
				n.gateway6 = onic["gateway6"].(string)
				n.addressMode, ok = onic["addressMode"].(string)
				utils.PanicIfError(ok, fmt.Errorf("cannot find 'addressMode' field for the nic[name:%s]", n.name))
			}

			n.isDefaultRoute = onic["isDefaultRoute"].(bool)
			if mtuFloat, ok := onic["mtu"].(float64); ok {
				n.mtu = int(mtuFloat)
			}
			if onic["l2type"] != nil {
				n.l2type = onic["l2type"].(string)
				n.category = onic["category"].(string)
			}
			if onic["vni"] != nil {
				n.vni = int(onic["vni"].(float64))
			}
			if onic["physicalInterface"] != nil {
				n.l2PhysicalInterface = onic["physicalInterface"].(string)
			}
			nics[n.name] = n
		}
	}

	type deviceName struct {
		expected string
		actual   string
		swap     string
	}

	devNames := make([]*deviceName, 0)

	// check integrity of nics
	for _, nic := range nics {
		utils.Assertf(nic.name != "", "name cannot be empty[mac:%s]", nic.mac)
		utils.Assertf(nic.mac != "", "mac cannot be empty[nicname:%s]", nic.name)
		utils.Assertf(nic.ip != "" || nic.ip6 != "", "ip cannot be empty[nicname: %s]", nic.name)
		/* for dual stack nic, nic.ip and nic.ip6 can not not empty at same time  */
		if nic.ip != "" {
			utils.Assertf(nic.netmask != "", "netmask cannot be empty[nicname:%s]", nic.name)
			utils.Assertf(nic.gateway != "", "gateway cannot be empty[nicname:%s]", nic.name)
		}

		if nic.ip6 != "" {
			utils.Assertf(nic.prefixLength != 0, "ipv6 prefix length cannot be empty[nicname:%s]", nic.name)
			utils.Assertf(nic.addressMode != "", "ipv6 address mode cannot be empty[nicname:%s]", nic.name)
			utils.Assertf(nic.gateway6 != "", "ipv6 gateway cannot be empty[nicname:%s]", nic.name)
		}

		nicname, err := utils.GetNicNameByMac(nic.mac)
		utils.PanicOnError(err)
		if nicname != nic.name {
			devNames = append(devNames, &deviceName{
				expected: nic.name,
				actual:   nicname,
			})
		}
	}

	if len(devNames) != 0 {
		// shutdown links and change to temporary names
		cmds := make([]string, 0)
		for i, devname := range devNames {
			devnum := 1000 + i

			devname.swap = fmt.Sprintf("eth%v", devnum)
			cmds = append(cmds, fmt.Sprintf("ip link set dev %v down", devname.actual))
			cmds = append(cmds, fmt.Sprintf("ip link set dev %v name %v", devname.actual, devname.swap))
		}

		b := utils.Bash{
			Command: strings.Join(cmds, "\n"),
		}

		b.Run()
		b.PanicIfError()

		// change temporary names to real names and bring up links
		cmds = make([]string, 0)
		for _, devname := range devNames {
			cmds = append(cmds, fmt.Sprintf("ip link set dev %v name %v", devname.swap, devname.expected))
			cmds = append(cmds, fmt.Sprintf("ip link set dev %v up", devname.expected))
		}

		b = utils.Bash{
			Command: strings.Join(cmds, "\n"),
		}

		b.Run()
		b.PanicIfError()
	}

	log.Debugf("haStatus %+v", haStatus)
	vyos := server.NewParserFromShowConfiguration()

	log.Debugf("[configure: publicKey]")
	tree := vyos.Tree

	sshkey := bootstrapInfo["publicKey"].(string)
	utils.Assert(sshkey != "", "cannot find 'publicKey' in bootstrap info")
	sshkeyparts := strings.Split(sshkey, " ")
	sshtype := sshkeyparts[0]
	key := sshkeyparts[1]
	id := sshkeyparts[2]

	tree.Setf("system login user vyos authentication public-keys %s key %s", id, key)
	tree.Setf("system login user vyos authentication public-keys %s type %s", id, sshtype)
	tree.Apply(true)

	makeAlias := func(nic *nic) string {
		result := ""
		if nic.l2type != "" {
			result += fmt.Sprintf("l2type:%s;", nic.l2type)
		}
		if nic.category != "" {
			result += fmt.Sprintf("category:%s;", nic.category)
		}
		if nic.l2PhysicalInterface != "" {
			result += fmt.Sprintf("physicalInterface:%s;", nic.l2PhysicalInterface)
		}
		result += fmt.Sprintf("vni:%v;", nic.vni)
		return result
	}

	setNicTree := server.NewParserFromShowConfiguration().Tree
	if haStatus != utils.NOHA && !utils.IsSLB() {
		/* for vpc ha router, set interface down, it will be up when ha selection is finished */
		for _, nic := range nics {
			if nic.name != "eth0" {
				setNicTree.Setf("interfaces ethernet %s disable", nic.name)
			}
		}
		setNicTree.Apply(true)
		setNicTree = server.NewParserFromShowConfiguration().Tree
	}

	setNic := func(nic *nic) {
		if nic.ip != "" {
			cidr, err := utils.NetmaskToCIDR(nic.netmask)
			utils.PanicOnError(err)
			//setNicTree.Setf("interfaces ethernet %s hw-id %s", nic.name, nic.mac)
			setNicTree.Setf("interfaces ethernet %s address %s", nic.name, fmt.Sprintf("%v/%v", nic.ip, cidr))
		}
		if nic.ip6 != "" {
			setNicTree.SetfWithoutCheckExisting("interfaces ethernet %s address %s", nic.name, fmt.Sprintf("%s/%d", nic.ip6, nic.prefixLength))
		}

		//set kernel arguments for specific nic
		err := os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/keep_addr_on_down", nic.name), []byte("1"), 0644)
		if err != nil {
			log.Warningf("enable nic %s keep_addr_on_down failed: %s!", nic.name, err)
		}

		err = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", nic.name), []byte("0"), 0644)
		if err != nil {
			log.Warningf("disable nic %s accept_dad failed: %s!", nic.name, err)
		}

		setNicTree.Setf("interfaces ethernet %s duplex auto", nic.name)
		setNicTree.SetNicSmpAffinity(nic.name, "auto")
		setNicTree.Setf("interfaces ethernet %s speed auto", nic.name)
		if nic.mtu != 0 {
			setNicTree.Setf("interfaces ethernet %s speed auto", nic.name)
			setNicTree.SetNicMtu(nic.name, nic.mtu)
		}
		if nic.isDefaultRoute {
			if nic.gateway != "" {
				setNicTree.Setf("protocols static route 0.0.0.0/0 next-hop %v", nic.gateway)
			}
			if nic.gateway6 != "" {
				setNicTree.Setf("protocols static route6 ::/0 next-hop %v", nic.gateway6)
			}
		}

		if nic.l2type != "" {
			setNicTree.Setf("interfaces ethernet %s description '%s'", nic.name, makeAlias(nic))
		}
	}

	sshport := bootstrapInfo["sshPort"].(float64)

	// configure firewall
	/* SkipVyosIptables is a flag to indicate how to configure firewall and nat */
	SkipVyosIptables := utils.IsSkipVyosIptables()
	log.Debugf("bootstrapInfo %+v", bootstrapInfo)
	log.Debugf("SkipVyosIptables %+v", SkipVyosIptables)

	log.Debugf("[configure: nic network]")
	applianceTypeTmp, found := bootstrapInfo["applianceVmSubType"]
	if !found {
		applianceTypeTmp = "None"
	}
	applianceType := applianceTypeTmp.(string)
	log.Debugf("applianceType %+v", applianceType)

	if SkipVyosIptables {
		for _, nic := range nics {
			var err error
			setNic(nic)
			if nic.isDefaultRoute {
				defaultNic = utils.Nic{Name: nic.name, Mac: nic.mac, Ip: nic.ip, Ip6: nic.ip6,
					Gateway: nic.gateway, Gateway6: nic.gateway6}
			}
			if nic.category == "Private" {
				err = utils.InitNicFirewall(nic.name, nic.ip, false, utils.IPTABLES_ACTION_REJECT)
			} else {
				err = utils.InitNicFirewall(nic.name, nic.ip, true, utils.IPTABLES_ACTION_REJECT)
			}
			if err != nil {
				log.Debugf("InitNicFirewall for nic: %s failed", err.Error())
			}
		}
	} else {
		for _, nic := range nics {
			setNic(nic)
			if nic.isDefaultRoute {
				defaultNic = utils.Nic{Name: nic.name, Mac: nic.mac, Ip: nic.ip, Ip6: nic.ip6,
					Gateway: nic.gateway, Gateway6: nic.gateway6}
			}
			setNicTree.SetFirewallOnInterface(nic.name, "local",
				"action accept",
				"state established enable",
				"state related enable",
				fmt.Sprintf("destination address %v", nic.ip),
			)

			setNicTree.SetFirewallOnInterface(nic.name, "local",
				"action accept",
				"protocol icmp",
				fmt.Sprintf("destination address %v", nic.ip),
			)

			setNicTree.SetZStackFirewallRuleOnInterface(nic.name, "behind", "in",
				"action accept",
				"state established enable",
				"state related enable",
			)

			setNicTree.SetFirewallWithRuleNumber(nic.name, "in", ROUTE_STATE_NEW_ENABLE_FIREWALL_RULE_NUMBER,
				"action accept",
				"state new enable",
			)

			// only allow ssh traffic on eth0, disable on others
			if nic.name == "eth0" {
				setNicTree.SetFirewallOnInterface(nic.name, "local",
					fmt.Sprintf("destination port %v", int(sshport)),
					fmt.Sprintf("destination address %v", nic.ip),
					"protocol tcp",
					"action accept",
				)
			} else {
				setNicTree.SetFirewallOnInterface(nic.name, "local",
					fmt.Sprintf("destination port %v", int(sshport)),
					fmt.Sprintf("destination address %v", nic.ip),
					"protocol tcp",
					"action reject",
				)
			}

			setNicTree.SetFirewallDefaultAction(nic.name, "local", "reject")
			setNicTree.SetFirewallDefaultAction(nic.name, "in", "reject")

			setNicTree.AttachFirewallToInterface(nic.name, "local")
			setNicTree.AttachFirewallToInterface(nic.name, "in")
		}
	}

	setNicTree.Apply(true)
	log.Debugf("[configure: radvd service]")
	radvdMap := make(utils.RadvdAttrsMap)
	if utils.IsSLB() {
		_ = radvdMap.StopService()
		log.Debugf("skip configure radvd service with SLB")
	} else {
		for _, nic := range nics {
			if nic.ip6 != "" && nic.prefixLength > 0 && nic.category == "Private" {
				radvdAttr := utils.NewRadvdAttrs().SetNicName(nic.name).SetIp6(nic.ip6, nic.prefixLength).SetMode(nic.addressMode)
				radvdMap[nic.name] = radvdAttr
			}
		}
		err := radvdMap.ConfigService()
		log.Debugf("configure radvd service error: %+v", err)
	}
	log.Debugf("[configure: ssh service]")
	setSshTree := server.NewParserFromShowConfiguration().Tree
	utils.Assert(sshport != 0, "sshport not found in bootstrap info")
	setSshTree.Setf("service ssh port %v", int(sshport))
	setSshTree.Setf("service ssh listen-address %v", eth0.ip)
	setSshTree.Apply(true)

	log.Debugf("[configure: system configuration]")
	setSysTree := server.NewParserFromShowConfiguration().Tree
	setSysTree.Set("system time-zone Asia/Shanghai")

	password, found := bootstrapInfo["vyosPassword"]
	utils.Assert(found && password != "", "vyosPassword cannot be empty")
	if !isOnVMwareHypervisor() {
		setSysTree.Setf("system login user vyos authentication plaintext-password %v", password)
	}

	/* create a cronjob to check sshd */
	setSysTree.Set("system task-scheduler task ssh interval 1")
	setSysTree.Set(fmt.Sprintf("system task-scheduler task ssh executable path '%s'", utils.GetCronjobFileSsh()))

	setSysTree.Apply(true)

	log.Debugf("[configure: ssh-key]")
	setKeyTree := server.NewParserFromShowConfiguration().Tree
	setKeyTree.Setf("system login user vyos authentication public-keys %s key %s", id, key)
	setKeyTree.Setf("system login user vyos authentication public-keys %s type %s", id, sshtype)
	setKeyTree.Apply(true)

	if strings.EqualFold(haStatus, utils.NOHA) {
		checkIpDuplicate()
	}

	arping := func(nicname, ip, gateway string) {
		b := utils.Bash{Command: fmt.Sprintf("sudo arping -q -A -w 2 -c 1 -I %s %s > /dev/null", nicname, ip)}
		b.Run()
	}

	arping6 := func(nicname, ip, gateway string) {
		b := utils.Bash{Command: fmt.Sprintf("sudo arping -6 -q -A -w 2 -c 1 -I %s %s > /dev/null", nicname, ip)}
		b.Run()
	}

	// arping to advocate our mac addresses
	if eth0.ip != "" {
		arping("eth0", eth0.ip, eth0.gateway)
	}
	if eth0.ip6 != "" {
		arping6("eth0", eth0.ip6, eth0.gateway)
	}

	for _, nic := range nics {
		if (nic.ip != "") {
			arping(nic.name, nic.ip, nic.gateway)
		}
		if (nic.ip6 != "") {
			arping6(nic.name, nic.ip6, eth0.gateway)
		}
	}

	mgmtNodeCidr := bootstrapInfo["managementNodeCidr"]
	if mgmtNodeCidr != nil {
		mgmtNodeCidrStr := mgmtNodeCidr.(string)
		nexthop, _ := utils.GetNexthop(mgmtNodeCidrStr)
		if nexthop != mgmtNic["gateway"].(string) {
			utils.AddRoute(mgmtNodeCidrStr, mgmtNic["gateway"].(string))
		}
	}

	/* this is workaround for ZStack*/
	log.Debugf("the vr gateway: %s, ipv6 gateway: %s at %s", defaultNic.Gateway, defaultNic.Gateway6, defaultNic.Name)
	if defaultNic.Gateway != "" {
		/* to fix ZSTAC-15742, the manage and public are in same cidr with different ranges,
		   then default route interface is management nic.
		   # route -n
		    Kernel IP routing table
		    Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
		    0.0.0.0         172.24.0.1      0.0.0.0         UG    0      0        0 eth0  ### should be eth1
		   in this case, we need change the default route to public route
		   to make vpc ha work, even add route failed, it will make zvrboot boot fail */
		bash := utils.Bash{
			Command: fmt.Sprintf("route -n| grep -w %s|grep -v %s", defaultNic.Gateway, defaultNic.Name),
		}
		ret, _, _, err := bash.RunWithReturn()
		if err == nil && ret == 0 {
			tree := server.NewParserFromShowConfiguration().Tree
			tree.Deletef("protocols static route 0.0.0.0/0 next-hop %v", defaultNic.Gateway)
			tree.Apply(true)

			b := utils.Bash{
				Command: fmt.Sprintf("ip route add default via %s dev %s", defaultNic.Gateway, defaultNic.Name),
			}
			b.Run()
		}
	}

	utils.WriteDefaultHaScript(&defaultNic)
}

func startZvr() {
	path := "/etc/init.d/zstack-virtualrouteragent"
	if utils.IsEuler2203() {
		path = "/usr/local/bin/zstack-virtualrouteragent"
	}
	b := utils.Bash{
		Command:  fmt.Sprintf("bash -x %s restart >> /tmp/agentRestart.log 2>&1", path),
	}
	b.Run()
	b.PanicIfError()
}

func init() {
	os.Remove(getNetworkHealthStatusPath())
	flag.BoolVar(&utils.CommandVersion, "version", false, "version for zvr")
}

func main() {
	flag.Parse()

	if utils.CommandVersion {
		utils.ModuleName = ModuleName
		utils.PrintBuildInfo()
		os.Exit(0)
	}

	utils.InitVyosVersion()
	utils.InitLog(getZvrbootLogPath(), false)
	waitIptablesServiceOnline()
	if isOnVMwareHypervisor() {
		parseEsxBootInfo()
	} else {
		waitVirtioPortOnline()
		parseKvmBootInfo()
	}
	log.Debugf("zvrboot main: os %s, kernel version: %s", utils.Vyos_version, utils.Kernel_version)
	utils.InitBootStrapInfo()
	if utils.IsEnableVyosCmd() {
		configureVyos()
	} else {
		configureSystem()
	}
	startZvr()
	log.Debugf("successfully configured the sysmtem and bootstrap the zstack virtual router agents")
}
