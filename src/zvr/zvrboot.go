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

	type Nic struct {
		mac string
		ip string
		name string
		netmask string
		isDefaultRoute bool
		gateway string
	}

	allNicsByMac := make(map[string]Nic)

	nicsByNames, err := utils.GetAllNics(); utils.PanicOnError(err)
	for _, nic := range nicsByNames {
		n := Nic{
			mac: nic.Mac,
			name: nic.Name,
		}
		allNicsByMac[n.mac] = n
	}

	setNic := func(nic Nic) {
		cidr, err := utils.NetmaskToCIDR(nic.netmask); utils.PanicOnError(err)
		tree.Setf("interfaces ethernet %s address %s", nic.name, fmt.Sprintf("%v/%v", nic.ip, cidr))
		tree.Setf("interfaces ethernet %s duplex auto", nic.name)
		tree.Setf("interfaces ethernet %s smp_affinity auto", nic.name)
		tree.Setf("interfaces ethernet %s speed auto", nic.name)
		if nic.isDefaultRoute {
			tree.Setf("system gateway-address %v", nic.gateway)
		}
	}

	mgmtNic := bootstrapInfo["managementNic"].(map[string]interface{})
	if mgmtNic == nil {
		panic(errors.New("no field 'managementNic' in bootstrap info"))
	}

	eth0 := func() Nic {
		for _, nic := range allNicsByMac {
			if nic.name == "eth0" {
				return nic
			}
		}
		panic("should not be here")
	}()

	mgmtMac, ok := mgmtNic["mac"]; utils.PanicIfError(ok, errors.New("cannot find 'mac' field for the management nic"))
	utils.Assert(eth0.mac == mgmtMac.(string),  fmt.Sprintf("the management nic[eth0] has the mac[%v] different from expected[%v]",
		eth0.mac, mgmtMac))
	eth0.netmask, ok = mgmtNic["netmask"].(string); utils.PanicIfError(ok, errors.New("cannot find 'netmask' field for the management nic"))
	eth0.ip, ok = mgmtNic["ip"].(string); utils.PanicIfError(ok, errors.New("cannot find 'ip' field for the management nic"))
	_, eth0.isDefaultRoute = mgmtNic["isDefaultRoute"].(bool)
	eth0.gateway = mgmtNic["gateway"].(string)
	setNic(eth0)

	otherNics := bootstrapInfo["additionalNics"].([]interface{})
	if otherNics != nil {
		for _, o := range otherNics {
			onic := o.(map[string]interface{})
			mac, ok := onic["mac"]; utils.PanicIfError(ok, errors.New("cannot find 'mac' field for the nic"))
			n := func() Nic {
				for _, nic := range allNicsByMac {
					if nic.mac == mac.(string) {
						return nic
					}
				}
				panic("should not be here")
			}()

			n.netmask, ok = onic["netmask"].(string); utils.PanicIfError(ok, fmt.Errorf("cannot find 'netmask' field for the nic[mac:%s]", mac))
			n.ip, ok = onic["ip"].(string); utils.PanicIfError(ok, fmt.Errorf("cannot find 'ip' field for the nic[mac:%s]", mac))
			_, n.isDefaultRoute = onic["isDefaultRoute"].(bool)
			setNic(n)
		}
	}

	sshport := bootstrapInfo["sshPort"].(float64)
	utils.Assert(sshport != 0, "sshport not found in bootstrap info")
	tree.Setf("service ssh port %v", int(sshport))

	// configure firewall
	tree.Set("firewall name default default-action reject")

	for _, nic := range allNicsByMac {
		tree.SetFirewallOnInterface(nic.name, "local",
			"action accept",
			"state established enable",
			"state related enable",
		)
		tree.SetFirewallOnInterface(nic.name, "local",
			"action accept",
			"protocol icmp",
		)

		tree.SetFirewallOnInterface(nic.name, "in",
			"action accept",
			"state established enable",
			"state related enable",
		)
		tree.SetFirewallOnInterface(nic.name, "in",
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

		tree.AttachFirewallToInterface(nic.name, "local")
		tree.AttachFirewallToInterface(nic.name, "in")
	}

	tree.Apply(true)

	arping := func(nicname, ip, gateway string) {
		b := utils.Bash{ Command: fmt.Sprintf("arping -A -U -c 1 -I %s -s %s %s", nicname, ip, gateway) }
		b.Run()
	}

	// arping to advocate our mac addresses
	arping("eth0", eth0.ip, eth0.gateway)
	for _, nic := range allNicsByMac {
		arping(nic.name, nic.ip, nic.gateway)
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
