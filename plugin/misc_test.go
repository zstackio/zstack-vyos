package plugin

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"text/template"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	gomega "github.com/onsi/gomega"
)

var _ = Describe("misc_test", func() {

	It("prepare env ...", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"misc_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		configureAllNicsForUT()
	})

	It("test add callback route", func() {
		ipInPubL3, _ := utils.GetFreePubL3Ip()
		defer utils.ReleasePubL3Ip(ipInPubL3)

		server.CALLBACK_IP = ipInPubL3
		addRouteIfCallbackIpChanged(true)
		gomega.Expect(utils.CheckZStackRouteExists(server.CALLBACK_IP)).To(gomega.BeTrue(),
			"failed to add the callback route for the first time.")

		utils.DeleteRouteIfExists(server.CALLBACK_IP)
		addRouteIfCallbackIpChanged(true)

		gomega.Expect(utils.CheckZStackRouteExists(server.CALLBACK_IP)).To(gomega.BeTrue(),
			"failed to add the callback route for the second time.")

		utils.DeleteRouteIfExists(server.CALLBACK_IP)
		addRouteIfCallbackIpChanged(false)
		gomega.Expect(utils.CheckZStackRouteExists(server.CALLBACK_IP)).To(gomega.BeFalse(),
			"route should not be added this time.")
	})

	It("[REPLACE_VYOS]: test cronjob", func() {
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetEnableVyosCmdForUT(false)
		cleanUpCrondConfig()
		configTaskScheduler()

		checkTaskScheduler()
		checkCrondProcess()
	})

	It("destroy env ...", func() {
		utils.CleanTestEnvForUT()
	})
})

func cleanUpCrondConfig() {
	bash := utils.Bash{
		Command: "rm -f /home/vyos/zvr/.zstack_config/cronjob",
		Sudo:    true,
	}
	bash.Run()
}
func checkCrondProcess() bool {
	bash := utils.Bash{
		Command: "ps -ef | grep '/usr/sbin/cron' | grep -v grep",
		Sudo:    true,
	}

	ret, _, _, _ := bash.RunWithReturn()

	return ret == 0
}

func checkTaskScheduler() {
	job1 := utils.NewCronjob().SetId(1).SetCommand(utils.GetCronjobFileSsh()).SetMinute("*/1")
	job2 := utils.NewCronjob().SetId(2).SetCommand(utils.GetCronjobFileZvrMonitor()).SetMinute("*/1")
	job3 := utils.NewCronjob().SetId(3).SetCommand(fmt.Sprintf("/usr/bin/flock -xn /tmp/file-monitor.lock -c %s", utils.GetCronjobFileMonitor())).SetMinute("0").SetHour("*/1")
	job4 := utils.NewCronjob().SetId(4).SetCommand(utils.GetCronjobFileRsyslog()).SetMinute("*/1")
	//job5 := utils.NewCronjob().SetId(5).SetCommand("/usr/bin/top -b -n 1 -H >> /var/log/top.log").SetMinute("*/1")

	c := utils.CronjobMap{
		1: job1,
		2: job2,
		3: job3,
		4: job4,
		//5: job5,
	}

	/*testMap := make(utils.CronjobMap)
	err := utils.JsonLoadConfig(utils.CROND_JSON_FILE, &testMap)
	Expect(err).To(BeNil(), "load crond json error: %+v", err)

	ret := reflect.DeepEqual(c, testMap)
	Expect(ret).To(BeTrue(), "attr map should equal")*/

	buf := bytes.Buffer{}
	tmpl, err := template.New("crond.conf").Parse(utils.CrondTemplate)
	Expect(err).To(BeNil(), "template parse error: %+v", err)
	err = tmpl.Execute(&buf, c)
	Expect(err).To(BeNil(), "template execute error: %+v", err)
	err = ioutil.WriteFile("/tmp/misc_test", buf.Bytes(), 0664)
	Expect(err).To(BeNil(), "template write error: %+v", err)

	checkDiffConfig(utils.CROND_CONFIG_FILE, "/tmp/misc_test")
}

func checkDiffConfig(srcfile string, dstfile string) {
	src, err := ioutil.ReadFile(srcfile)
	Expect(err).To(BeNil(), "read src file error: %+v", err)
	dst, err := ioutil.ReadFile(dstfile)
	Expect(err).To(BeNil(), "read dst file error: %+v", err)

	isEqual := bytes.Equal(src, dst)
	Expect(isEqual).To(BeTrue(), "src file should equal dst file, but not")
}

func cleanPluginMaps() {
	// dns map
	dnsServers = map[string]string{}
	nicNames = map[string]string{}

	// pf map
	pfMap = make(map[string]dnatInfo, PortForwardingInfoMaxSize)

	// qos map
	totalQosRules = make(map[string]interfaceInOutQosRules, MAX_PUBLIC_INTERFACE)

	// eip map
	eipMap = make(map[string]eipInfo, EipInfoMaxSize)
	eipIpset = nil
	ipsets, _ := utils.GetCurrentIpSet()
	for _, ipset := range ipsets {
		if ipset.Name == EIP_IPSET_NAME {
			eipIpset = ipset
			break
		}
	}

	// lb map
	gobetweenListeners = map[string]*GBListener{}
	haproxyListeners = map[string]*HaproxyListener{}

	// ipsec map
	ipsecMap = make(map[string]ipsecInfo, IPSecInfoMaxSize)

	// nic map
	nicIps := utils.GetBootStrapNicInfo()
	for _, nic := range nicIps {
		nicsMap[nic.Name] = nic
	}
}
