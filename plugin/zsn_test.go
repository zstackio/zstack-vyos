package plugin

import (
	"bytes"
	"io/ioutil"
	"reflect"
	"text/template"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("zsn_test", func() {
	It("[REPLACE_VYOS]: pre test env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"zsn_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetEnableVyosCmdForUT(false)
		cleanUpCrondConfig()
	})

	It("[REPLACE_VYOS]: test enable zsn-agent", func() {
		cmd := &setDistributedRoutingReq{Enabled: true}
		_ = setDistributedRouting(cmd)
		//Expect(err).To(BeNil(), "setDistributedRouting error: %+v", err)
		checkZsnCronJob(true)
	})
	It("[REPLACE_VYOS]: test disable zsn-agent", func() {
		cmd := &setDistributedRoutingReq{Enabled: false}
		_ = setDistributedRouting(cmd)
		//Expect(err).To(BeNil(), "setDistributedRouting error: %+v", err)
		checkZsnCronJob(false)
		utils.SetEnableVyosCmdForUT(true)
		utils.CleanTestEnvForUT()
	})
})

func checkZsnCronJob(enable bool) {
	if enable {
		testMap := utils.CronjobMap{}
		zsnJob := utils.NewCronjob().SetId(6).SetCommand(utils.Cronjob_file_zsn).SetMinute("*/1")
		cronJobMap := utils.CronjobMap{6: zsnJob}
		err := utils.JsonLoadConfig("/home/vyos/zvr/.zstack_config/cronjob", &testMap)
		Expect(err).To(BeNil(), "JsonLoadConfig cronjob error : %+v", err)

		ret := reflect.DeepEqual(cronJobMap, testMap)
		Expect(ret).To(BeTrue(), "attr map should equal")

		buf := bytes.Buffer{}
		tmpl, err := template.New("crond.conf").Parse(utils.CrondTemplate)
		Expect(err).To(BeNil(), "template parse error: %+v", err)
		err = tmpl.Execute(&buf, cronJobMap)
		Expect(err).To(BeNil(), "template execute error: %+v", err)
		err = ioutil.WriteFile("/tmp/zsn_test", buf.Bytes(), 0664)
		Expect(err).To(BeNil(), "template write error: %+v", err)
		checkDiffConfig(utils.CROND_CONFIG_FILE, "/tmp/zsn_test")
	} else {
		testMap := utils.CronjobMap{}
		err := utils.JsonLoadConfig("/home/vyos/zvr/.zstack_config/cronjob", &testMap)
		Expect(err).To(BeNil(), "JsonLoadConfig cronjob error : %+v", err)
		Expect(len(testMap)).To(Equal(0), "zsn cronjob should be nil")
	}
}
