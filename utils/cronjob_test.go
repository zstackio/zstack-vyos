package utils

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"text/template"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("cronjob_test", func() {
	var globalMap CronjobMap
	It("[CRONJOB]: test pre env", func() {
		InitLog(GetVyosUtLogDir()+"cronjob_test.log", IsRuingUT())
		globalMap = make(CronjobMap)
		cleanUpCrondConfig()
	})
	It("[CRONJOB]: test add 3 jobs", func() {
		job1 := NewCronjob().SetId(1).SetCommand("echo hello1 > /tmp/crond_test").SetMinute("*/1").SetHour("*").SetDay("*").SetMonth("*").SetWeek("*").SetDescription("test job1")
		job2 := NewCronjob().SetId(2).SetCommand("echo hello2 > /tmp/crond_test").SetMinute("*/1").SetHour("1").SetDay("*").SetMonth("*").SetWeek("*").SetDescription("test job2")
		job3 := NewCronjob().SetId(3).SetCommand("echo hello3 > /tmp/crond_test").SetMinute("*/1").SetHour("1").SetDay("1").SetMonth("*").SetWeek("*").SetDescription("test job3")
		cronjobMap := CronjobMap{
			1: job1,
			2: job2,
			3: job3,
		}
		err := cronjobMap.ConfigService()
		Expect(err).To(BeNil(), "ConfigService() should return nil, but %+v", err)
		isRunning := checkCrondProcess()
		Expect(isRunning).To(BeTrue(), "crond service should running")

		globalMap[1] = job1
		globalMap[2] = job2
		globalMap[3] = job3
		checkCrondConfig(globalMap)
	})
	It("[CRONJOB]: test delete 1 job", func() {
		job1 := NewCronjob().SetId(1).SetDelete()
		cronjobMap := CronjobMap{
			1: job1,
		}
		err := cronjobMap.ConfigService()
		Expect(err).To(BeNil(), "ConfigService() should return nil, but %+v", err)
		isRunning := checkCrondProcess()
		Expect(isRunning).To(BeTrue(), "crond service should running")

		delete(globalMap, 1)
		checkCrondConfig(globalMap)
	})
	It("[CRONJOB]: test add 1 new job", func() {
		job4 := NewCronjob().SetId(4).SetCommand("echo hello4 > /tmp/crond_test").SetDay("*").SetDescription("test job4")
		cronjobMap := CronjobMap{
			4: job4,
		}
		err := cronjobMap.ConfigService()
		Expect(err).To(BeNil(), "ConfigService() should return nil, but %+v", err)
		isRunning := checkCrondProcess()
		Expect(isRunning).To(BeTrue(), "crond service should running")

		globalMap[4] = job4
		checkCrondConfig(globalMap)
	})
	It("[CRONJOB]: test replace 1 job", func() {
		newJob := NewCronjob().SetId(2).SetCommand("echo hello2 > /tmp/crond_test").SetMinute("1").SetDescription("test new job2")
		cronjobMap := CronjobMap{
			2: newJob,
		}
		err := cronjobMap.ConfigService()
		Expect(err).To(BeNil(), "ConfigService() should return nil, but %+v", err)
		isRunning := checkCrondProcess()
		Expect(isRunning).To(BeTrue(), "crond service should running")

		globalMap[2] = newJob
		checkCrondConfig(globalMap)
	})
})

func cleanUpCrondConfig() {
	bash := Bash{
		Command: fmt.Sprintf("rm -f %s", filepath.Join(GetZvrZsConfigPath(), "cronjob")),
		Sudo:    true,
	}
	bash.Run()
}
func checkCrondProcess() bool {
	bash := Bash{
		Command: "ps -ef | grep '/usr/sbin/cron' | grep -v grep",
		Sudo:    true,
	}

	ret, _, _, _ := bash.RunWithReturn()

	return ret == 0
}

func checkCrondConfig(c CronjobMap) {
	testMap := make(CronjobMap)
	err := JsonLoadConfig(CROND_JSON_FILE, &testMap)
	Expect(err).To(BeNil(), fmt.Sprintf("load crond json error: %+v", err))

	ret := reflect.DeepEqual(c, testMap)
	Expect(ret).To(BeTrue(), "attr map should equal")

	buf := bytes.Buffer{}
	tmpl, err := template.New("crond.conf").Parse(CrondTemplate)
	Expect(err).To(BeNil(), "template parse error: %+v", err)
	err = tmpl.Execute(&buf, c)
	Expect(err).To(BeNil(), "template execute error: %+v", err)
	err = ioutil.WriteFile("/tmp/radvd_tmp_conf", buf.Bytes(), 0755)
	Expect(err).To(BeNil(), "template write error: %+v", err)

	checkDiffConfig(CROND_CONFIG_FILE, "/tmp/radvd_tmp_conf")
}
