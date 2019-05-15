package utils

import (
	"io/ioutil"
	log "github.com/Sirupsen/logrus"
	"encoding/json"
)

const (
	BOOTSTRAP_INFO_CACHE = "/home/vyos/zvr/bootstrap-info.json"
	DEFAULT_SSH_PORT = 22
)

const  (
	NOHA = "NoHa"
	HAMASTER = "Master"
	HABACKUP = "Backup"
)

var bootstrapInfo map[string]interface{} = make(map[string]interface{})

func GetSshPortFromBootInfo() float64 {
	port, ok := bootstrapInfo["sshPort"].(float64)
	if !ok {
		return DEFAULT_SSH_PORT
	}

	return port
}

func GetMgmtInfoFromBootInfo() map[string]interface{} {
	mgmtNic := bootstrapInfo["managementNic"].(map[string]interface{})
	return mgmtNic
}

func IsSkipVyosIptables() bool {
	SkipVyosIptables, ok := bootstrapInfo["SkipVyosIptables"].(bool)
	if !ok {
		return false
	}

	return SkipVyosIptables
}

func InitBootStrapInfo() {
	content, err := ioutil.ReadFile(BOOTSTRAP_INFO_CACHE); PanicOnError(err)
	if len(content) == 0 {
		log.Debugf("no content in %s, can not get mgmt gateway", BOOTSTRAP_INFO_CACHE)
	}

	if err := json.Unmarshal(content, &bootstrapInfo); err != nil {
		log.Debugf("can not parse info from %s, can not get mgmt gateway", BOOTSTRAP_INFO_CACHE)
	}
}

func IsHaEabled() bool {
	if _, ok := bootstrapInfo["haStatus"]; ok {
		if bootstrapInfo["haStatus"].(string) != NOHA {
			return true
		}
	}

	return false
}

func GetVirtualRouterUuid()  string {
	if _, ok := bootstrapInfo["uuid"]; ok {
		return bootstrapInfo["uuid"].(string)
	}

	return ""
}