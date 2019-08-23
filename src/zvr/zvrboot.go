package main

import (
	"zvr/utils"
	"time"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"encoding/json"
	"github.com/pkg/errors"
	"fmt"
	"zvr/server"
	"strings"
	"os"
)

const (
	VIRTIO_PORT_PATH = "/dev/virtio-ports/applianceVm.vport"
	BOOTSTRAP_INFO_CACHE = "/home/vyos/zvr/bootstrap-info.json"
	TMP_LOCATION_FOR_ESX = "/tmp/bootstrap-info.json"
	// use this rule number to set a rule which confirm route entry work issue ZSTAC-6170
	ROUTE_STATE_NEW_ENABLE_FIREWALL_RULE_NUMBER = 9999
)

type nic struct {
	mac string
	ip string
	name string
	netmask string
	isDefaultRoute bool
	gateway string
	category string
	l2type string
	l2PhysicalInterface string
	vni int
}

var bootstrapInfo map[string]interface{} = make(map[string]interface{})
var nics map[string]*nic = make(map[string]*nic)

func waitIptablesServiceOnline()  {
	bash := utils.Bash{
		Command: "/sbin/iptables-save",
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
		ok, err := utils.PathExists(VIRTIO_PORT_PATH); utils.PanicOnError(err)
		if !ok {
			log.Debugf("%s doesn't not exist, wait it ...", VIRTIO_PORT_PATH)
		}
		return ok
	}, time.Duration(120)*time.Second, time.Duration(500)*time.Millisecond)
}

func isOnVMwareHypervisor() bool {
	bash := utils.Bash{
		Command: "dmesg | grep -q 'Hypervisor.*VMware'",
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

		content, err := ioutil.ReadFile(TMP_LOCATION_FOR_ESX); utils.PanicOnError(err)
		if err = json.Unmarshal(content, &bootstrapInfo); err != nil {
			panic(errors.Wrap(err, fmt.Sprintf("unable to JSON parse:\n %s", string(content))))
		}

		err = utils.MkdirForFile(BOOTSTRAP_INFO_CACHE, 0666); utils.PanicOnError(err)
		err = os.Rename(TMP_LOCATION_FOR_ESX, BOOTSTRAP_INFO_CACHE); utils.PanicOnError(err)
		err = os.Chmod(BOOTSTRAP_INFO_CACHE, 0777); utils.PanicOnError(err)
		log.Debugf("recieved bootstrap info:\n%s", string(content))
		return true
	}, time.Duration(300)*time.Second, time.Duration(1)*time.Second)
}

func parseKvmBootInfo() {
	utils.LoopRunUntilSuccessOrTimeout(func() bool {
		content, err := ioutil.ReadFile(VIRTIO_PORT_PATH); utils.PanicOnError(err)
		if len(content) == 0 {
			log.Debugf("no content in %s, it may not be ready, wait it ...", VIRTIO_PORT_PATH)
			return false
		}

		if err := json.Unmarshal(content, &bootstrapInfo); err != nil {
			panic(errors.Wrap(err, fmt.Sprintf("unable to JSON parse:\n %s", string(content))))
		}

		err = utils.MkdirForFile(BOOTSTRAP_INFO_CACHE, 0666); utils.PanicOnError(err)
		err = ioutil.WriteFile(BOOTSTRAP_INFO_CACHE, content, 0666); utils.PanicOnError(err)
		err = os.Chmod(BOOTSTRAP_INFO_CACHE, 0777); utils.PanicOnError(err)
		log.Debugf("recieved bootstrap info:\n%s", string(content))
		return true
	}, time.Duration(300)*time.Second, time.Duration(1)*time.Second)
}

func resetVyos()  {
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
}

func configureVyos() {
	resetVyos()
	var defaultNic, defaultGW string = "", ""

	mgmtNic := bootstrapInfo["managementNic"].(map[string]interface{})
	if mgmtNic == nil {
		panic(errors.New("no field 'managementNic' in bootstrap info"))
	}

	haStatus := "NoHa"
	if v, ok := bootstrapInfo["haStatus"]; ok {
		haStatus = v.(string)
	}

	eth0 := &nic{name: "eth0" }
	var ok bool
	eth0.mac, ok = mgmtNic["mac"].(string); utils.PanicIfError(ok, errors.New("cannot find 'mac' field for the management nic"))
	eth0.netmask, ok = mgmtNic["netmask"].(string); utils.PanicIfError(ok, errors.New("cannot find 'netmask' field for the management nic"))
	eth0.ip, ok = mgmtNic["ip"].(string); utils.PanicIfError(ok, errors.New("cannot find 'ip' field for the management nic"))
	eth0.isDefaultRoute = mgmtNic["isDefaultRoute"].(bool)
	eth0.gateway = mgmtNic["gateway"].(string)
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
			n.name, ok = onic["deviceName"].(string); utils.PanicIfError(ok, fmt.Errorf("cannot find 'deviceName' field for the nic"))
			n.mac, ok = onic["mac"].(string); utils.PanicIfError(ok, errors.New("cannot find 'mac' field for the nic"))
			n.netmask, ok = onic["netmask"].(string); utils.PanicIfError(ok, fmt.Errorf("cannot find 'netmask' field for the nic[name:%s]", n.name))
			n.ip, ok = onic["ip"].(string); utils.PanicIfError(ok, fmt.Errorf("cannot find 'ip' field for the nic[name:%s]", n.name))
			n.gateway = onic["gateway"].(string)
			n.isDefaultRoute = onic["isDefaultRoute"].(bool)
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
		utils.Assertf(nic.ip != "", "ip cannot be empty[nicname: %s]", nic.name)
		utils.Assertf(nic.gateway != "", "gateway cannot be empty[nicname:%s]", nic.name)
		utils.Assertf(nic.netmask != "", "netmask cannot be empty[nicname:%s]", nic.name)
		utils.Assertf(nic.mac != "", "mac cannot be empty[nicname:%s]", nic.name)

		nicname, err := utils.GetNicNameByMac(nic.mac); utils.PanicOnError(err)
		if nicname != nic.name {
			devNames = append(devNames, &deviceName{
				expected: nic.name,
				actual: nicname,
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

	log.Debugf("haStatus %+v, nics %+v", haStatus, nics)
	cmds := []string{}
	if haStatus != "NoHa" {
		for _, nic := range nics {
			/* when ha enaled, all nics except eth0 is shutdown when bootup */
			if nic.name == "eth0" {
				continue
			}

			cmds = append(cmds, fmt.Sprintf("ip link set dev %v down", nic.name))
		}

		if len(cmds) != 0 {
			b := utils.Bash{
				Command: strings.Join(cmds, "\n"),
			}

			b.Run()
			b.PanicIfError()
		}
	}

	vyos := server.NewParserFromShowConfiguration()
	tree := vyos.Tree

	sshkey := bootstrapInfo["publicKey"].(string)
	utils.Assert(sshkey != "", "cannot find 'publicKey' in bootstrap info")
	sshkeyparts := strings.Split(sshkey, " ")
	sshtype := sshkeyparts[0]
	key := sshkeyparts[1]
	id := sshkeyparts[2]

	tree.Setf("system login user vyos authentication public-keys %s key %s", id, key)
	tree.Setf("system login user vyos authentication public-keys %s type %s", id, sshtype)

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

	setNic := func(nic *nic) {
		cidr, err := utils.NetmaskToCIDR(nic.netmask); utils.PanicOnError(err)
		//tree.Setf("interfaces ethernet %s hw-id %s", nic.name, nic.mac)
		tree.Setf("interfaces ethernet %s address %s", nic.name, fmt.Sprintf("%v/%v", nic.ip, cidr))
		tree.Setf("interfaces ethernet %s duplex auto", nic.name)
		tree.Setf("interfaces ethernet %s smp_affinity auto", nic.name)
		tree.Setf("interfaces ethernet %s speed auto", nic.name)
		if nic.isDefaultRoute {
			tree.Setf("system gateway-address %v", nic.gateway)
		}

		if nic.l2type != "" {
			b := utils.NewBash()
			b.Command = fmt.Sprintf("ip link set dev %s alias '%s'", nic.name, makeAlias(nic))
			b.Run()
		}
	}

	sshport := bootstrapInfo["sshPort"].(float64)
	utils.Assert(sshport != 0, "sshport not found in bootstrap info")
	tree.Setf("service ssh port %v", int(sshport))
	tree.Setf("service ssh listen-address %v", eth0.ip)

	// configure firewall
	/* SkipVyosIptables is a flag to indicate how to configure firewall and nat */
	SkipVyosIptables := false
	if v, ok := bootstrapInfo["SkipVyosIptables"]; ok {
		SkipVyosIptables = v.(bool)
	}
	log.Debugf("bootstrapInfo %+v", bootstrapInfo)
	log.Debugf("SkipVyosIptables %+v", SkipVyosIptables)

	if (SkipVyosIptables) {
		for _, nic := range nics {
			var err error
			setNic(nic)
			if nic.category == "Private" {
				err = utils.InitNicFirewall(nic.name, nic.ip, false, utils.REJECT)
			} else {
				err = utils.InitNicFirewall(nic.name, nic.ip, true, utils.REJECT)
			}
			if err != nil {
				log.Debugf("InitNicFirewall for nic: %s failed", err.Error())
			}
		}
	} else {
		for _, nic := range nics {
			setNic(nic)
			if nic.isDefaultRoute {
				defaultGW = nic.gateway
				defaultNic = nic.name
			}
			tree.SetFirewallOnInterface(nic.name, "local",
				"action accept",
				"state established enable",
				"state related enable",
				fmt.Sprintf("destination address %v", nic.ip),
			)

			tree.SetFirewallOnInterface(nic.name, "local",
				"action accept",
				"protocol icmp",
				fmt.Sprintf("destination address %v", nic.ip),
			)

			if nic.category == "Private" {
				tree.SetZStackFirewallRuleOnInterface(nic.name, "behind","in",
					"action accept",
					"state established enable",
					"state related enable",
					"state invalid enable",
					"state new enable",
				)
			} else {
				tree.SetZStackFirewallRuleOnInterface(nic.name, "behind","in",
					"action accept",
					"state established enable",
					"state related enable",
				)
			}

			tree.SetFirewallWithRuleNumber(nic.name, "in", ROUTE_STATE_NEW_ENABLE_FIREWALL_RULE_NUMBER,
				"action accept",
				"state new enable",
			)

			tree.SetZStackFirewallRuleOnInterface(nic.name, "behind","in",
				"action accept",
				"protocol icmp",
			)

			// only allow ssh traffic on eth0, disable on others
			if nic.name == "eth0" {
				tree.SetFirewallOnInterface(nic.name, "local",
					fmt.Sprintf("destination port %v", int(sshport)),
					fmt.Sprintf("destination address %v", nic.ip),
					"protocol tcp",
					"action accept",
				)
			} else {
				tree.SetFirewallOnInterface(nic.name, "local",
					fmt.Sprintf("destination port %v", int(sshport)),
					fmt.Sprintf("destination address %v", nic.ip),
					"protocol tcp",
					"action reject",
				)
			}

			tree.SetFirewallDefaultAction(nic.name, "local", "reject")
			tree.SetFirewallDefaultAction(nic.name, "in", "reject")

			tree.AttachFirewallToInterface(nic.name, "local")
			tree.AttachFirewallToInterface(nic.name, "in")
		}
	}

	tree.Set("system time-zone Asia/Shanghai")

	password, found := bootstrapInfo["vyosPassword"]; utils.Assert(found && password != "", "vyosPassword cannot be empty")
	if !isOnVMwareHypervisor() {
		tree.Setf("system login user vyos authentication plaintext-password %v", password)
	}

	tree.Apply(true)

	arping := func(nicname, ip, gateway string) {
		b := utils.Bash{Command: fmt.Sprintf("sudo arping -q -A -w 1.5 -c 1 -I %s %s > /dev/null", nicname, ip) }
		b.Run()
	}

	// arping to advocate our mac addresses
	arping("eth0", eth0.ip, eth0.gateway)
	for _, nic := range nics {
		arping(nic.name, nic.ip, nic.gateway)
	}

	mgmtNodeIp := bootstrapInfo["managementNodeIp"]
	if mgmtNodeIp == nil {
		log.Debugf("can not get management node ip from bootstrap info, skip to config route")
	} else {
		mgmtNodeIpStr := mgmtNodeIp.(string)
		if (utils.CheckMgmtCidrContainsIp(mgmtNodeIpStr, mgmtNic) == false) {
			err := utils.SetZStackRoute(mgmtNodeIpStr, "eth0", mgmtNic["gateway"].(string));
			utils.PanicOnError(err)
		} else if utils.GetNicForRoute(mgmtNodeIpStr) != "eth0" {
			err := utils.SetZStackRoute(mgmtNodeIpStr, "eth0", ""); utils.PanicOnError(err)
		} else {
			log.Debugf("the cidr of vr mgmt contains callback ip, skip to configure route")
		}
	}
	/* this is workaround for zstac*/
	log.Debugf("the vr public network %s at %s", defaultGW, defaultNic)
	if defaultGW != "" {
		//check default gw in route and it's workaround for ZSTAC-15742, the manage and public are in same cidr with different ranges
		bash := utils.Bash{
			Command: fmt.Sprintf("route -n| grep -w %s|grep -w %s", defaultGW, defaultNic),
		}
		ret, _, _, err := bash.RunWithReturn()
		if err == nil && ret != 0 {
			tree := server.NewParserFromShowConfiguration().Tree
			tree.Deletef("system gateway-address %v", defaultGW)
			tree.Apply(true)
			b := utils.Bash{
				Command: fmt.Sprintf("ip route add default via %s dev %s", defaultGW, defaultNic),
			}
			b.Run()
			b.PanicIfError()
		}
	}
}

func startZvr()  {
	b := utils.Bash{
		Command: "sudo mount -t tmpfs -o size=64M tmpfs /tmp; bash -x /etc/init.d/zstack-virtualrouteragent restart >> /tmp/agentRestart.log 2>&1",
	}
	b.Run()
	b.PanicIfError()
}

func main() {
	utils.InitLog("/home/vyos/zvr/zvrboot.log", false)
	waitIptablesServiceOnline()
	if isOnVMwareHypervisor() {
		parseEsxBootInfo()
	} else {
		waitVirtioPortOnline()
		parseKvmBootInfo()
	}
	configureVyos()
	startZvr()
	log.Debugf("successfully configured the sysmtem and bootstrap the zstack virtual router agents")
}
