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
)

var bootstrapInfo map[string]interface{} = make(map[string]interface{})

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

func parseBootInfo() {
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

func configureVyos()  {
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

	nicsByMac := make(map[string]utils.Nic)
	nicsByNames, err := utils.GetAllNics(); utils.PanicOnError(err)
	for _, nic := range nicsByNames {
		nicsByMac[nic.Mac] = nic
	}

	setNic := func(nicname, ip, netmask string, defaultRoute bool) {
		cidr, err := utils.NetmaskToCIDR(netmask); utils.PanicOnError(err)
		tree.Setf("interfaces ethernet %s address %s", nicname, fmt.Sprintf("%v/%v", ip, cidr))
		tree.Setf("interfaces ethernet %s duplex auto", nicname)
		tree.Setf("interfaces ethernet %s smp_affinity auto", nicname)
		tree.Setf("interfaces ethernet %s speed auto", nicname)
	}

	mgmtNic := bootstrapInfo["managementNic"].(map[string]interface{})
	if mgmtNic == nil {
		panic(errors.New("no field 'managementNic' in bootstrap info"))
	}

	mgmtMac, ok := mgmtNic["mac"]; utils.PanicIfError(ok, errors.New("cannot find 'mac' field for the management nic"))
	mgmtNetmask, ok := mgmtNic["netmask"]; utils.PanicIfError(ok, errors.New("cannot find 'netmask' field for the management nic"))
	mgmtIp, ok := mgmtNic["ip"]; utils.PanicIfError(ok, errors.New("cannot find 'ip' field for the management nic"))
	mn, ok := nicsByMac[mgmtMac.(string)]; utils.PanicIfError(ok, fmt.Errorf("cannot find the management nic[mac:%s]", mgmtMac))
	utils.PanicIfError(mn.Name == "eth0", fmt.Errorf("the management nic is not eth0 but %s", mn.Name))
	_, ok = mgmtNic["isDefaultRoute"]
	setNic("eth0", mgmtIp.(string), mgmtNetmask.(string), ok)

	otherNics := bootstrapInfo["additionalNics"].([]interface{})
	if otherNics != nil {
		for _, o := range otherNics {
			onic := o.(map[string]interface{})
			mac, ok := onic["mac"]; utils.PanicIfError(ok, errors.New("cannot find 'mac' field for the nic"))
			netmask, ok := onic["netmask"]; utils.PanicIfError(ok, fmt.Errorf("cannot find 'netmask' field for the nic[mac:%s]", mac))
			ip, ok := onic["ip"]; utils.PanicIfError(ok, fmt.Errorf("cannot find 'ip' field for the nic[mac:%s]", mac))
			n, ok := nicsByMac[mac.(string)]; utils.PanicIfError(ok, fmt.Errorf("the nic with mac[%s] is not found in the system", mac))

			_, ok = onic["isDefaultRoute"]
			setNic(n.Name, ip.(string), netmask.(string), ok)
		}
	}

	sshport := bootstrapInfo["sshPort"].(float64)
	utils.Assert(sshport != 0, "sshport not found in bootstrap info")
	tree.Setf("service ssh port %v", int(sshport))

	// configure firewall
	nics, err := utils.GetAllNics(); utils.PanicOnError(err)
	tree.Set("firewall name default default-action reject")

	for _, nic := range nics {
		tree.SetFirewallOnInterface(nic.Name, "local",
			"action accept",
			"state established enable",
			"state related enable",
		)
		tree.SetFirewallOnInterface(nic.Name, "local",
			"action accept",
			"protocol icmp",
		)

		tree.SetFirewallOnInterface(nic.Name, "in",
			"action accept",
			"state established enable",
			"state related enable",
		)
		tree.SetFirewallOnInterface(nic,nic, "in",
			"action accept",
			"protocol icmp",
		)

		// only allow ssh traffic on eth0, disable on others
		if nic.Name == "eth0" {
			tree.SetFirewallOnInterface(nic.Name, "local", fmt.Sprintf("destination port %v", int(sshport)))
			tree.SetFirewallOnInterface(nic.Name, "local", "protocol tcp")
			tree.SetFirewallOnInterface(nic.Name, "local", "action accept")
		} else {
			tree.SetFirewallOnInterface(nic.Name, "local", fmt.Sprintf("destination port %v", int(sshport)))
			tree.SetFirewallOnInterface(nic.Name, "local", "protocol tcp")
			tree.SetFirewallOnInterface(nic.Name, "local", "action reject")
		}

		tree.AttachFirewallToInterface(nic.Name, "local")
		tree.AttachFirewallToInterface(nic.Name, "in")
	}

	tree.Apply(false)

	arping := func(nicname, ip, gateway string) {
		b := utils.Bash{ Command: fmt.Sprintf("arping -A -U -c 1 -I %s -s %s %s", nicname, ip, gateway) }
		b.Run()
	}

	// arping to advocate our mac addresses
	arping("eth0", mgmtIp.(string), mgmtNic["gateway"].(string))
	if otherNics != nil {
		for _, o := range otherNics {
			onic := o.(map[string]interface{})
			mac, _ := onic["mac"]
			n, _ := nicsByMac[mac.(string)]
			arping(n.Name, onic["ip"].(string), onic["gateway"].(string))
		}
	}
}

func startZvr()  {
	b := utils.Bash{
		Command: "/etc/init.d/zstack-virtualrouteragent restart",
	}
	b.Run()
	b.PanicIfError()
}

func main() {
	utils.InitLog("/home/vyos/zvr/zvrboot.log", false)
	waitIptablesServiceOnline()
	waitVirtioPortOnline()
	parseBootInfo()
	configureVyos()
	startZvr()
	log.Debugf("successfully configured the sysmtem and bootstrap the zstack virtual router agents")
}
