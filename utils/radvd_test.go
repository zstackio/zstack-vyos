package utils

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"reflect"
	"text/template"

	log "github.com/sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func GetRadvdJsonFile() {
	return filepath.Join(GetZvrRootPath(), ".zstack_config/radvd")
}

var _ = Describe("radvd_test", func() {
	var globalMap RadvdAttrsMap
	It("[RADVD]: test pre env", func() {
		InitLog(GetVyosUtLogDir()+"radvd_test.log", false)
		globalMap = make(RadvdAttrsMap)
		cleanUpConfig()
	})

	It("[RADVD]: test add nic", func() {
		log.Debugf("######## test add nic ########")
		radvdAttr1 := NewRadvdAttrs().SetNicName("eth1").SetIp6("2001::1", 64).SetMode("Stateful-DHCP")
		radvdAttr2 := NewRadvdAttrs().SetNicName("eth2").SetIp6("2001::2", 64).SetMode("Stateless-DHCP")
		radvdAttr3 := NewRadvdAttrs().SetNicName("eth3").SetIp6("2001::3", 64).SetMode("SLAAC")
		radvdMap := RadvdAttrsMap{
			"eth1": radvdAttr1,
			"eth2": radvdAttr2,
			"eth3": radvdAttr3,
		}
		err := radvdMap.ConfigService()
		Expect(err).To(BeNil(), "ConfigService() should return nil, but %+v", err)
		isRunning := checkRadvdProcess()
		Expect(isRunning).To(BeTrue(), "radvd process should running")

		globalMap["eth1"] = radvdAttr1
		globalMap["eth2"] = radvdAttr2
		globalMap["eth3"] = radvdAttr3
		checkRadvdConfig(globalMap)
	})

	It("[RADVD]: test delete nic", func() {
		log.Debugf("######## test delete nic ########")
		radvdAttr2 := NewRadvdAttrs().SetNicName("eth2").SetIp6("2001::2", 64).SetMode("Stateless-DHCP").SetDelete()
		radvdMap := RadvdAttrsMap{
			"eth2": radvdAttr2,
		}
		err := radvdMap.ConfigService()
		Expect(err).To(BeNil(), "ConfigService() should return nil, but %+v", err)
		isRunning := checkRadvdProcess()
		Expect(isRunning).To(BeTrue(), "radvd process should running")

		delete(globalMap, "eth2")
		checkRadvdConfig(globalMap)
	})

	It("[RADVD]: test add nic again", func() {
		log.Debugf("######## test add nic again ########")
		radvdAttr4 := NewRadvdAttrs().SetNicName("eth4").SetIp6("2001::4", 64).SetMode("Stateless-DHCP")
		radvdMap := RadvdAttrsMap{
			"eth4": radvdAttr4,
		}
		err := radvdMap.ConfigService()
		Expect(err).To(BeNil(), "ConfigService() should return nil, but %+v", err)
		isRunning := checkRadvdProcess()
		Expect(isRunning).To(BeTrue(), "radvd process should running")

		globalMap["eth4"] = radvdAttr4
		checkRadvdConfig(globalMap)
	})

	It("[RADVD]: test delete config", func() {
		log.Debugf("######## test delete config ########")
		radvdAttr1 := NewRadvdAttrs().SetNicName("eth1").SetIp6("2001::1", 64).SetMode("Stateful-DHCP").SetDelete()
		radvdAttr3 := NewRadvdAttrs().SetNicName("eth3").SetIp6("2001::3", 64).SetMode("SLAAC").SetDelete()
		radvdAttr4 := NewRadvdAttrs().SetNicName("eth4").SetIp6("2001::4", 64).SetMode("Stateless-DHCP").SetDelete()
		radvdMap := RadvdAttrsMap{
			"eth1": radvdAttr1,
			"eth3": radvdAttr3,
			"eth4": radvdAttr4,
		}
		err := radvdMap.ConfigService()
		Expect(err).To(BeNil(), "ConfigService() should return nil, but %+v", err)
		isRunning := checkRadvdProcess()
		Expect(isRunning).To(BeFalse(), "radvd process should stop")

		delete(globalMap, "eth1")
		delete(globalMap, "eth3")
		delete(globalMap, "eth4")
		checkRadvdConfig(globalMap)
	})

	It("[RADVD]: test destory env", func() {
		log.Debugf("######## test destory env ########")
		cleanUpConfig()
	})
})

func cleanUpConfig() {
	bash := Bash{
		Command: fmt.Sprintf("rm -f %s; sudo pkill -9 radvd", GetRadvdJsonFile())
		Sudo:    true,
	}
	bash.Run()
}

func checkRadvdProcess() bool {
	bash := Bash{
		Command: fmt.Sprintf("ps -ef | grep '%s' | grep -v grep", RADVD_BIN_PATH),
		Sudo:    true,
	}
	ret, _, _, _ := bash.RunWithReturn()

	return ret == 0
}

func checkRadvdConfig(r RadvdAttrsMap) {
	testMap := make(RadvdAttrsMap)
	err := JsonLoadConfig(GetRadvdJsonFile(), &testMap)
	Expect(err).To(BeNil(), fmt.Sprintf("load radvd json error: %+v", err))

	ret := reflect.DeepEqual(r, testMap)
	Expect(ret).To(BeTrue(), "attr map should equal")

	buf := bytes.Buffer{}
	tmpl, err := template.New("radvd.conf").Parse(radvdTemplate)
	Expect(err).To(BeNil(), "template parse error: %+v", err)
	err = tmpl.Execute(&buf, r)
	Expect(err).To(BeNil(), "template execute error: %+v", err)
	err = ioutil.WriteFile("/tmp/radvd.conf", buf.Bytes(), 0755)
	Expect(err).To(BeNil(), "template write error: %+v", err)

	checkDiffConfig(RADVD_CONFIG_FILE, "/tmp/radvd.conf")

}

func checkDiffConfig(srcfile string, dstfile string) {
	src, err := ioutil.ReadFile(srcfile)
	Expect(err).To(BeNil(), "read src file error: %+v", err)
	dst, err := ioutil.ReadFile(dstfile)
	Expect(err).To(BeNil(), "read dst file error: %+v", err)

	isEqual := bytes.Equal(src, dst)
	Expect(isEqual).To(BeTrue(), "src file should equal dst file, but not")
}
