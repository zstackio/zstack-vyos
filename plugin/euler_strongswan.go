package plugin

import (
	"bytes"
	"fmt"
	log "github.com/sirupsen/logrus"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
	"zstack-vyos/utils"
)

const SwanConnectionConfPath = "/etc/strongswan/swanctl/conf.d/"
const swanConnectionTemplate = `
connections {
    {{ .ConnName }} {
        remote_addrs = {{.Right}}
        {{- if ne .Left ""}}   
        local_addrs = {{.Left}}
        {{- else }}
        local_addrs = any
        {{- end}}

        local {
            auth = {{.Authby}}
            id = {{.Leftid}}
        }

        remote {
           auth = {{.Authby}}
           id = {{.Rightid}}
        }

        children {
            {{ .ConnName }} {
                local_ts  = {{.Leftsubnet}}
                remote_ts = {{.Rightsubnet}}

                {{- if ne .Lifetime ""}}
                life_time = {{.Lifetime}}
                {{- end}}
                {{- if ne .Esp ""}}
                esp_proposals = {{.Esp}}
                {{- end}}
                {{- if ne .Dpdaction ""}}
                dpd_action = {{.Dpdaction}}
                {{- end}}
                start_action = start
                policies_fwd_out = yes
                mode = tunnel
            }
        }
        
        mobike = no
        version  = {{.IkeVersion}}
        {{- if ne .Ikelifetime ""}}
        reauth_time = {{.Ikelifetime}}
        {{- end}}
        {{- if ne .RekeyTime ""}}  
        rekey_time = {{.RekeyTime }}
        {{- end}}
        {{- if ne .Ike ""}}
        proposals = {{.Ike}}
        {{- end}}
        {{- if ne .Dpddelay ""}}
        dpd_delay ={{.Dpddelay}}
        {{- end}}
        {{- if ne .Aggressive "no"}}
        aggressive = yes
        {{- end}}
        if_id_in = %unique
        if_id_out = %unique
    }
}

secrets {
   ike-1 {
      id-1 = {{.Leftid}}
      secret = {{.Secret}}
   }

   ike-2 {
      id-2 = {{.Rightid}}
      secret = {{.Secret}}
   }
}
`

type EulerStrongSWan struct {
}

func getEulerIpsecConnConfPath(conf ipsecConf) string {
	return filepath.Join(SwanConnectionConfPath, conf.ConnName+".conf")
}

func (driver *EulerStrongSWan) DriverType() string {
	return ipsec_driver_strongswan_euler
}

func (driver *EulerStrongSWan) ExistConnWorking() bool {
	return false
}

func (driver *EulerStrongSWan) CreateIpsecConns(cmd *CreateIPsecCmd) error {
	//swanctl --initiate --ike xxx --child xxx to start a ipsec connection
	var conns []*ipsecConf

	for _, info := range cmd.Infos {
		err, conn := getStrongswanConnConf(&info) // 转换配置
		if err != nil {
			return err
		}
		conns = append(conns, conn)
	}

	for _, conn := range conns {
		var buf bytes.Buffer
		tmpl, err := template.New(conn.ConnName).Parse(swanConnectionTemplate)
		utils.PanicOnError(err)
		err = tmpl.Execute(&buf, conn)
		utils.PanicOnError(err)
		err = os.WriteFile(getEulerIpsecConnConfPath(*conn), buf.Bytes(), 0644)
		utils.PanicOnError(err)

		b := utils.Bash{
			Command: fmt.Sprintf("swanctl -q;nohup swanctl -i -i %s -c %s > /dev/null 2>&1 &", conn.ConnName, conn.ConnName),
			Sudo:    true,
		}
		err = b.Run()
		utils.PanicOnError(err)
	}

	return nil
}

func (driver *EulerStrongSWan) DeleteIpsecConns(cmd *DeleteIPsecCmd) error {
	for _, info := range cmd.Infos {
		err, conf := getStrongswanConnConf(&info) // 转换配置
		if err != nil {
			log.Error(err.Error())
		}

		err = os.Remove(getEulerIpsecConnConfPath(*conf))
		if err != nil {
			log.Errorf("delete ipsec conf file failed:%s", err)
		}

		b := utils.Bash{
			Command: fmt.Sprintf("swanctl -q;nohup swanctl -t --ike %s > /dev/null 2>&1 &", conf.ConnName),
			Sudo:    true,
		}

		ret, _, _, err := b.RunWithReturn()
		if ret != 0 || err != nil {
			log.Errorf("delete ipsec conn failed: ret %d, err: %+v", ret, err)
		}
	}
	return nil
}

func (driver *EulerStrongSWan) ModifyIpsecConns(cmd *updateIPsecCmd) error {
	/* TODO: UI doesn't has this api */
	return nil
}

func (driver *EulerStrongSWan) SyncIpsecConns(cmd *SyncIPsecCmd) []string {

	var downConnList []string
	var conns []*ipsecConf
	downConnMap := map[string]*ipsecConf{}
	connMd5Map := map[string]string{}
	md5ChangedConnMap := map[string]string{}

	for _, info := range cmd.Infos {
		err, conn := getStrongswanConnConf(&info) // 转换配置
		if err != nil {
			log.Error(err.Error())
			return downConnList
		}
		conns = append(conns, conn)
	}

	for _, conn := range conns {
		var buf bytes.Buffer
		tmpl, err := template.New(conn.ConnName).Parse(swanConnectionTemplate)
		utils.PanicOnError(err)
		err = tmpl.Execute(&buf, conn)
		utils.PanicOnError(err)

		md5, err := getFileChecksum(getEulerIpsecConnConfPath(*conn))
		if err == nil {
			connMd5Map[conn.ConnName] = md5
		} else {
			connMd5Map[conn.ConnName] = ""
		}
		err = os.WriteFile(getEulerIpsecConnConfPath(*conn), buf.Bytes(), 0644)
		utils.PanicOnError(err)
	}

	for _, conn := range conns {
		downConnMap[conn.ConnName] = conn
		md5, err := getFileChecksum(getEulerIpsecConnConfPath(*conn))
		if err != nil {
			md5 = ""
		}
		if md5 != connMd5Map[conn.ConnName] {
			md5ChangedConnMap[conn.ConnName] = conn.ConnName
		}
	}

	for connName, _ := range md5ChangedConnMap {
		b := utils.Bash{
			Command: fmt.Sprintf("swanctl -q;nohup swanctl -i -i %s -c %s > /dev/null 2>&1 &", connName, connName),
			Sudo:    true,
		}
		err := b.Run()
		log.Debugf("init ipsec connection[uuid:%s] failed %+v", conns, err)
	}

	// wait ipsec up
	utils.Retry(func() error {
		if len(downConnMap) == 0 {
			return nil
		}

		for _, conn := range downConnMap {
			if isEulerIpsecConnUp(conn.ConnName) {
				delete(downConnMap, conn.ConnName)
			}
		}

		if len(downConnMap) == 0 {
			return nil
		}

		downConnList = []string{}
		for _, conn := range downConnMap {
			downConnList = append(downConnList, conn.ConnName)
		}

		return fmt.Errorf("there are ipsec conns: %v is not established", downConnList)
	}, 1, 5)

	return downConnList
}

func (driver *EulerStrongSWan) GetIpsecLog(cmd *getIPsecLogCmd) string {
	ipsecLog := ""
	log.Debug("start get ipsec log")
	for _, str := range utils.ReadLastNLine(ipsec_vyos_path_log, cmd.Lines) {
		ipsecLog = strings.TrimSpace(str) + "\n" + ipsecLog
	}
	return ipsecLog
}

func CleanIpSecconnectionFiles() {
	utils.SudoRmFile(SwanConnectionConfPath)
}

func isEulerIpsecConnUp(connName string) bool {
	b := utils.Bash{
		Command: fmt.Sprintf("swanctl -l --ike %s | grep 'ESTABLISHED'", connName),
		Sudo:    true,
	}

	ret, _, _, err := b.RunWithReturn()
	if ret != 0 || err != nil {
		return false
	}

	return true
}

func getAllIpsecConnStatus() map[string]string {
	ipsecStateMap := make(map[string]string)
	dir, err := os.Open(SwanConnectionConfPath)
	if err != nil {
		return ipsecStateMap
	}
	defer dir.Close()

	fileInfos, err := dir.Readdir(-1)
	if err != nil {
		return ipsecStateMap
	}

	// 打印文件列表
	for _, fileInfo := range fileInfos {
		connName := strings.Split(fileInfo.Name(), ".")[0]
		if isEulerIpsecConnUp(connName) {
			ipsecStateMap[connName] = IPSEC_STATE_UP
		} else {
			ipsecStateMap[connName] = IPSEC_STATE_DOWN
		}
	}

	return ipsecStateMap
}

func checkIpsecConnectStatusTask() {
	taskTimer := time.NewTicker(time.Second * 60)
	for {
		select {
		case <-taskTimer.C:
			ipsecStateMap := getAllIpsecConnStatus()
			log.Debugf("getAllIpsecConnStatus map: %+v", ipsecStateMap)
			for conn, status := range ipsecStateMap {
				if status == IPSEC_STATE_DOWN {
					b := utils.Bash{
						Command: fmt.Sprintf("swanctl -q;nohup swanctl -i -i %s -c %s > /dev/null 2>&1 &", conn, conn),
						Sudo:    true,
					}
					err := b.Run()
					log.Errorf("restart failed: %+v", err)
				}
			}
		}
	}
}

func InitStrongswanService() {
	if !utils.IsEuler2203() {
		return
	}

	b := utils.Bash{
		Command: fmt.Sprintf("systemctl status strongswan || systemctl restart strongswan"),
		Sudo:    true,
	}
	err := b.Run()
	log.Errorf("start strongswan failed: %+v", err)

	go checkIpsecConnectStatusTask()
}
