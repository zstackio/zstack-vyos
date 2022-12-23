package plugin

import (
	"bytes"
	"io/ioutil"
	"reflect"
	"text/template"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	gomega "github.com/onsi/gomega"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
)

var _ = Describe("misc_test", func() {
	var nicCmd *configureNicCmd

	It("prepare env ...", func() {
		utils.InitLog(utils.VYOS_UT_LOG_FOLDER+"misc_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		nicCmd = &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.MgtNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)
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
		utils.SetEnableVyosCmdForUT(true)
		nicCmd = &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		removeNic(nicCmd)
		deleteMgtNicFirewall(true)
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
	job1 := utils.NewCronjob().SetId(1).SetCommand(utils.Cronjob_file_ssh).SetMinute("*/1")
	job2 := utils.NewCronjob().SetId(2).SetCommand(utils.Cronjob_file_zvrMonitor).SetMinute("*/1")
	job3 := utils.NewCronjob().SetId(3).SetCommand(utils.Cronjob_file_fileMonitor).SetMinute("*/1")
	job4 := utils.NewCronjob().SetId(4).SetCommand(utils.Cronjob_file_rsyslog).SetMinute("*/1")
	job5 := utils.NewCronjob().SetId(5).SetCommand("/usr/bin/top b -n 1 -H >> /var/log/top.log").SetMinute("*/1")

	c := utils.CronjobMap{
		1: job1,
		2: job2,
		3: job3,
		4: job4,
		5: job5,
	}

	testMap := make(utils.CronjobMap)
	err := utils.JsonLoadConfig(utils.CROND_JSON_FILE, &testMap)
	Expect(err).To(BeNil(), "load crond json error: %+v", err)

	ret := reflect.DeepEqual(c, testMap)
	Expect(ret).To(BeTrue(), "attr map should equal")

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
