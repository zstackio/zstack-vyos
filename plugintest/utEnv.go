package plugintest

import (
	"fmt"
	"sync"
	"zstack-vyos/utils"
)

type UtEnv struct {
	envCreated bool
	envLock    sync.Mutex

	MgtNicForUT utils.NicInfo
	PubNicForUT utils.NicInfo
	PriNicForUT utils.NicInfo

	PriNicForUT1 utils.NicInfo

	additionalPubNicForUT1 utils.NicInfo
	additionalPubNicForUT2 utils.NicInfo

	ConfigTcForVipQos bool
	EnableVyosCmd     bool
	SkipVyosIptables  bool
}

func (env *UtEnv) AddPeerAddr(nicName, addr string) {
	err := utils.IpAddrAdd(nicName+"-peer", addr)
	utils.PanicOnError(err)
	//log.Debugf("add peer addr success, nicName: %s, addr: %s", nicName, addr)
}

func (env *UtEnv) GetNicMac(nicName string) string {
	switch nicName {
	case "mgt":
		return env.MgtNicForUT.Mac
	case "pub":
		return env.PubNicForUT.Mac
	case "pri":
		return env.PriNicForUT.Mac
	}
	utils.PanicOnError(fmt.Errorf("can not found nic"))
	return ""
}
