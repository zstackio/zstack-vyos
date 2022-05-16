package utils

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"text/template"

	log "github.com/Sirupsen/logrus"
)

const (
	RADVD_BIN_PATH         = "/usr/sbin/radvd -u radvd -p /var/run/radvd/radvd.pid"
	RADVD_CONFIG_FILE      = "/etc/radvd.conf"
	RADVD_CONFIG_FILE_TEMP = "/home/vyos/radvd.conf"
	RADVD_PID_FILE         = "/var/run/radvd/radvd.pid"
	RADVD_CHROOT_DIR       = "/var/run/radvd"
	RADVD_JSON_FILE        = "/home/vyos/zvr/.zstack_config/radvd"
	RA_MAX_INTERVAL        = 60
	RA_MIN_INTERVAL        = 15
	FLAG_ON                = "on"
	FLAG_OFF               = "off"
)

const radvdTemplate = `#
# autogenerated by ZStack, DO NOT MODIFY IT
#
{{range .}}interface {{.NicName}} {
	IgnoreIfMissing on;
	AdvSendAdvert on;
	AdvOtherConfigFlag {{.AdvOtherConfigFlag}};
	AdvDefaultLifetime 180;
	AdvLinkMTU 0;
	AdvCurHopLimit 64;
	AdvReachableTime 0;
	MaxRtrAdvInterval {{.MaxRtrAdvInterval}};
	MinRtrAdvInterval {{.MinRtrAdvInterval}};
	AdvDefaultPreference medium;
	AdvRetransTimer 0;
	AdvManagedFlag {{.AdvManagedFlag}};
	prefix {{.Address}}/{{.PrefixLength}} {
		AdvPreferredLifetime 604800;
		AdvAutonomous {{.AdvAutonomous}};
		AdvOnLink on;
		AdvValidLifetime 2592000;
	};
};
{{end}}`

type RadvdAttrsMap map[string]*RadvdAttrs

type RadvdAttrs struct {
	NicName            string
	Address            string
	PrefixLength       int
	MaxRtrAdvInterval  int
	MinRtrAdvInterval  int
	AdvManagedFlag     string
	AdvOtherConfigFlag string
	AdvAutonomous      string
	isDelete           bool
}

func NewRadvdAttrs() *RadvdAttrs {
	newRadvdServer := RadvdAttrs{
		MaxRtrAdvInterval:  RA_MAX_INTERVAL,
		MinRtrAdvInterval:  RA_MIN_INTERVAL,
		AdvManagedFlag:     FLAG_ON,
		AdvOtherConfigFlag: FLAG_ON,
		AdvAutonomous:      FLAG_OFF,
		isDelete:           false,
	}

	return &newRadvdServer
}

func (r *RadvdAttrs) SetNicName(name string) *RadvdAttrs {
	if name != "" {
		r.NicName = name
	}

	return r
}

func (r *RadvdAttrs) SetIp6(address string, prefix int) *RadvdAttrs {
	if address != "" && prefix > 0 {
		r.Address = address
		r.PrefixLength = prefix
	}

	return r
}

func (r *RadvdAttrs) SetDelete() *RadvdAttrs {
	r.isDelete = true

	return r
}

func (r *RadvdAttrs) SetMode(addressMode string) *RadvdAttrs {
	if addressMode == "" {
		return r
	}
	switch addressMode {
	case "Stateful-DHCP":
		r.AdvManagedFlag = FLAG_ON
		r.AdvOtherConfigFlag = FLAG_ON
		r.AdvAutonomous = FLAG_OFF
	case "Stateless-DHCP":
		r.AdvManagedFlag = FLAG_OFF
		r.AdvOtherConfigFlag = FLAG_ON
		r.AdvAutonomous = FLAG_ON
	case "SLAAC":
		r.AdvManagedFlag = FLAG_OFF
		r.AdvOtherConfigFlag = FLAG_OFF
		r.AdvAutonomous = FLAG_ON
	}

	return r
}

func (r RadvdAttrsMap) ConfigService() error {
	var (
		buf  bytes.Buffer
		tmpl *template.Template
		err  error
	)
	attrsMap := make(RadvdAttrsMap)

	if err := JsonLoadConfig(RADVD_JSON_FILE, &attrsMap); err != nil {
		return err
	}
	for k, v := range r {
		if v.isDelete {
			log.Debugf("radvd: delete nic: %s", k)
			delete(attrsMap, k)
		} else {
			log.Debugf("radvd: add nic: %s", k)
			attrsMap[k] = v
		}
	}
	if tmpl, err = template.New("radvd.conf").Parse(radvdTemplate); err != nil {
		return err
	}
	if err = tmpl.Execute(&buf, attrsMap); err != nil {
		return err
	}

	if err = ioutil.WriteFile(RADVD_CONFIG_FILE_TEMP, buf.Bytes(), 0664); err != nil {
		return err
	}
	bash := Bash{
		Command: fmt.Sprintf("mv %s %s", RADVD_CONFIG_FILE_TEMP, RADVD_CONFIG_FILE),
		Sudo:    true,
	}
	bash.Run()

	if err = JsonStoreConfig(RADVD_JSON_FILE, attrsMap); err != nil {
		return err
	}

	if len(attrsMap) == 0 {
		return r.StopService()
	}

	return r.RestarServer()
}

func (r RadvdAttrsMap) RestarServer() error {
	if ok, err := PathExists(RADVD_PID_FILE); err != nil || !ok {
		bash := Bash{
			Command: fmt.Sprintf("mkdir -p %s; chown -R radvd:root %s", RADVD_CHROOT_DIR, RADVD_CHROOT_DIR),
			Sudo:    true,
		}
		bash.Run()
	}

	bash := Bash{
		Command: fmt.Sprintf("pkill -9 radvd; %s", RADVD_BIN_PATH),
		Sudo:    true,
	}

	return bash.Run()
}

//should not care about its return value
func (r RadvdAttrsMap) StopService() error {
	bash := Bash{
		Command: "pkill -9 radvd",
		Sudo:    true,
	}
	bash.Run()

	return nil
}