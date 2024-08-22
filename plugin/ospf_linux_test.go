package plugin

import (
	"fmt"
	"strings"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("ospf_linux_test", func() {
	var (
		nicCmd                                 *configureNicCmd
		area0, area1, area2, area3             areaInfo
		network0, network1, network2, network3 networkInfo
	)

	It("[REPLACE_VYOS]: test pre env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"ospf_linux_test.log", false)
		utils.CleanTestEnvForUT()
		cleanUpOspfConfig()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetEnableVyosCmdForUT(false)
		utils.SetSkipVyosIptables(true)
		nicCmd = &configureNicCmd{}

		log.Debugf("start test quagga ospfd")
		area0 = areaInfo{
			AreaId:    "0.0.0.0",
			AreaType:  Standard,
			AuthType:  Plaintext,
			AuthParam: "password",
		}
		network0 = networkInfo{
			NicMac:  utils.PubNicForUT.Mac,
			Network: "10.0.0.0/16",
			AreaId:  "0.0.0.0",
		}

		area1 = areaInfo{
			AreaId:    "0.0.0.1",
			AreaType:  Standard,
			AuthType:  MD5,
			AuthParam: "123/password",
		}
		network1 = networkInfo{
			NicMac:  utils.AdditionalPubNicsForUT[0].Mac,
			Network: "10.10.0.0/16",
			AreaId:  "0.0.0.1",
		}

		area2 = areaInfo{
			AreaId:    "0.0.0.2",
			AreaType:  Stub,
			AuthType:  None,
			AuthParam: "",
		}
		network2 = networkInfo{
			NicMac:  utils.PrivateNicsForUT[0].Mac,
			Network: "10.20.0.0/16",
			AreaId:  "0.0.0.2",
		}

		area3 = areaInfo{
			AreaId:    "0.0.0.3",
			AreaType:  Standard,
			AuthType:  None,
			AuthParam: "",
		}
		network3 = networkInfo{
			NicMac:  utils.PrivateNicsForUT[1].Mac,
			Network: "10.30.0.0/16",
			AreaId:  "0.0.0.3",
		}
	})

	It("[REPLACE_VYOS]: test add area0", func() {
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		configureNic(nicCmd)

		cmd := &setOspfCmd{
			RouterId:     utils.PubNicForUT.Ip,
			AreaInfos:    []areaInfo{area0},
			NetworkInfos: []networkInfo{network0},
		}
		configureOspfByVtysh(cmd)
		checkRouterId(cmd.RouterId)
		checkAreaConfigure([]areaInfo{area0}, nil)
		checkNetworkConfigure([]networkInfo{network0}, nil)
		checkInterfaceConfigure(network0.NicMac, string(area0.AuthType), area0.AuthParam)
	})

	It("[REPLACE_VYOS]: test add area1", func() {
		cmd := &setOspfCmd{
			RouterId:     utils.PubNicForUT.Ip,
			AreaInfos:    []areaInfo{area0, area1},
			NetworkInfos: []networkInfo{network0, network1},
		}
		configureOspfByVtysh(cmd)
		checkRouterId(cmd.RouterId)
		checkAreaConfigure([]areaInfo{area0, area1}, nil)
		checkNetworkConfigure([]networkInfo{network0, network1}, nil)
		checkInterfaceConfigure(network0.NicMac, string(area0.AuthType), area0.AuthParam)
		checkInterfaceConfigure(network1.NicMac, string(area1.AuthType), area1.AuthParam)
	})

	It("[REPLACE_VYOS]: test add area2 and delete area1", func() {
		cmd := &setOspfCmd{
			RouterId:     utils.PubNicForUT.Ip,
			AreaInfos:    []areaInfo{area0, area2},
			NetworkInfos: []networkInfo{network0, network2},
		}
		configureOspfByVtysh(cmd)
		checkRouterId(cmd.RouterId)
		checkAreaConfigure([]areaInfo{area0, area2}, []areaInfo{area1})
		checkNetworkConfigure([]networkInfo{network0, network2}, []networkInfo{network1})
		checkInterfaceConfigure(network0.NicMac, string(area0.AuthType), area0.AuthParam)
		checkInterfaceConfigure(network2.NicMac, string(area2.AuthType), area2.AuthParam)
	})

	It("[REPLACE_VYOS]: test add area3 and area1", func() {
		cmd := &setOspfCmd{
			RouterId:     utils.PubNicForUT.Ip,
			AreaInfos:    []areaInfo{area0, area1, area2, area3},
			NetworkInfos: []networkInfo{network0, network1, network2, network3},
		}
		configureOspfByVtysh(cmd)
		checkRouterId(cmd.RouterId)
		checkAreaConfigure([]areaInfo{area0, area1, area2, area3}, nil)
		checkNetworkConfigure([]networkInfo{network0, network1, network2, network3}, nil)
		checkInterfaceConfigure(network0.NicMac, string(area0.AuthType), area0.AuthParam)
		checkInterfaceConfigure(network1.NicMac, string(area1.AuthType), area1.AuthParam)
		checkInterfaceConfigure(network2.NicMac, string(area2.AuthType), area2.AuthParam)
		checkInterfaceConfigure(network3.NicMac, string(area3.AuthType), area3.AuthParam)
	})

	It("[REPLACE_VYOS]: test delete all area", func() {
		cmd := &setOspfCmd{
			RouterId:     utils.PubNicForUT.Ip,
			AreaInfos:    []areaInfo{},
			NetworkInfos: []networkInfo{},
		}
		configureOspfByVtysh(cmd)
		checkAreaConfigure(nil, []areaInfo{area0, area1, area2, area3})
		checkNetworkConfigure(nil, []networkInfo{network0, network1, network2, network3})
	})

	It("[REPLACE_VYOS]: test destory env", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkAreaConfigure(add []areaInfo, delete []areaInfo) {
	bash := utils.Bash{
		Command: "vtysh -d ospfd -c 'show running-config' -c 'exit' | grep '^ area' | sed 's/^ //'",
		Sudo:    true,
	}
	_, out, _, _ := bash.RunWithReturn()
	netCfg := strings.Split(out, "\n")
	temp := map[string]struct{}{}
	for _, val := range netCfg {
		temp[val] = struct{}{}
	}

	if len(add) != 0 {
		for _, info := range add {
			if info.AreaType == Stub {
				val := fmt.Sprintf("area %s stub", info.AreaId)
				_, ok := temp[val]
				Expect(ok).To(BeTrue(), "area config:[%s] should exist", val)
			}
			if info.AuthType == Plaintext {
				val := fmt.Sprintf("area %s authentication", info.AreaId)
				_, ok := temp[val]
				Expect(ok).To(BeTrue(), "area config:[%s] should exist", val)
			}
			if info.AuthType == MD5 {
				val := fmt.Sprintf("area %s authentication message-digest", info.AreaId)
				_, ok := temp[val]
				Expect(ok).To(BeTrue(), "area config:[%s] should exist", val)
			}
		}
	}
	if len(delete) != 0 {
		for _, info := range delete {
			if info.AreaType == Stub {
				val := fmt.Sprintf("area %s stub", info.AreaId)
				_, ok := temp[val]
				Expect(ok).To(BeFalse(), "area config:[%s] should be deleted", val)
			}
			if info.AuthType == Plaintext {
				val := fmt.Sprintf("area %s authentication", info.AreaId)
				_, ok := temp[val]
				Expect(ok).To(BeFalse(), "area config:[%s] should be deleted", val)
			}
			if info.AuthType == MD5 {
				val := fmt.Sprintf("area %s authentication message-digest", info.AreaId)
				_, ok := temp[val]
				Expect(ok).To(BeFalse(), "area config:[%s] should be deleted", val)
			}
		}
	}
}

func checkNetworkConfigure(add []networkInfo, delete []networkInfo) {
	bash := utils.Bash{
		Command: "vtysh -d ospfd -c 'show running-config' -c 'exit' | grep 'network' | sed 's/^ //'",
		Sudo:    true,
	}

	_, out, _, _ := bash.RunWithReturn()
	netCfg := strings.Split(out, "\n")
	temp := map[string]struct{}{}
	for _, val := range netCfg {
		temp[val] = struct{}{}
	}

	if len(add) != 0 {
		for _, info := range add {
			val := fmt.Sprintf("network %s area %s", info.Network, info.AreaId)
			_, ok := temp[val]
			Expect(ok).To(BeTrue(), "network configure:[%s] should exist", val)
		}
	}
	if len(delete) != 0 {
		for _, info := range delete {
			val := fmt.Sprintf("network %s area %s", info.Network, info.AreaId)
			_, ok := temp[val]
			Expect(ok).To(BeFalse(), "network configure:[%s] should be delete", val)
		}
	}

}

func checkInterfaceConfigure(nicMac string, authType string, authParam string) {
	nicName, _ := utils.GetNicNameByMac(nicMac)
	bash := utils.Bash{
		Command: fmt.Sprintf("vtysh -d ospfd -c 'show running-config' -c 'exit' | grep -A 2 'interface %s' | grep '^ ' | sed 's/^ //'", nicName),
		Sudo:    true,
	}
	_, out, _, _ := bash.RunWithReturn()
	netCfg := strings.Split(out, "\n")
	temp := map[string]struct{}{}
	for _, val := range netCfg {
		temp[val] = struct{}{}
	}
	if authType == string(Plaintext) {
		val1 := "ip ospf authentication"
		val2 := fmt.Sprintf("ip ospf authentication-key %s", authParam)
		_, ok := temp[val1]
		Expect(ok).To(BeTrue(), "interface config:[%s] should exist", val1)
		_, ok = temp[val2]
		Expect(ok).To(BeTrue(), "interface config:[%s] should exist", val2)
	}
	if authType == string(MD5) {
		tmp := strings.Split(authParam, "/")
		val1 := "ip ospf authentication message-digest"
		val2 := fmt.Sprintf("ip ospf message-digest-key %s md5 %s", tmp[0], tmp[1])
		_, ok := temp[val1]
		Expect(ok).To(BeTrue(), "interface config:[%s] should exist", val1)
		_, ok = temp[val2]
		Expect(ok).To(BeTrue(), "interface config:[%s] should exist", val2)
	}
}

func checkRouterId(routerId string) {
	bash := utils.Bash{
		Command: "vtysh -d ospfd -c 'show running-config' -c 'exit' | grep 'router-id' | sed 's/^ //'",
		Sudo:    true,
	}
	_, out, _, _ := bash.RunWithReturn()
	routerCfg := strings.TrimSuffix(out, "\n")
	val := fmt.Sprintf("ospf router-id %s", routerId)
	Expect(routerCfg).To(Equal(val), "router id [%s] should exist", val)
}

func cleanUpOspfConfig() {
	bash := utils.Bash{
		Command: fmt.Sprintf("rm -f %s", utils.OSPF_JSON_FILE),
		Sudo:    true,
	}
	bash.Run()
}
