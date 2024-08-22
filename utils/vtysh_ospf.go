package utils

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	Standard = "Standard"
	Stub     = "Stub"
	NSSA     = "NSSA"

	None      = "None"
	MD5       = "MD5"
	Plaintext = "Plaintext"
)

func GetOspfJsonFile() string {
	return filepath.Join(GetZvrZsConfigPath(), "ospf.json")
}

const ospfAddTemplate = `'configure terminal
router ospf
ospf router-id {{.RouterIdCmd}}
{{range $m, $n := .NetworkCmd}}
network {{$n.Network}} area {{$n.AreaId}}
{{- end}}
{{range $k, $v := .AreaCmd}}
{{if eq $v.Type "Stub"}}area {{$v.Id}} stub{{end}}
{{if eq $v.Auth "Plaintext"}}area {{$v.Id}} authentication{{else if eq $v.Auth "MD5"}}area {{$v.Id}} authentication message-digest{{end}}
{{- end}}
{{range $i, $j := .IfaceCmd}}
interface {{$j.Name}}
{{if eq $j.Auth "Plaintext"}}
ip ospf authentication
ip ospf authentication-key {{$j.Password}}
{{else if eq $j.Auth "MD5"}}
ip ospf authentication message-digest
ip ospf message-digest-key {{$j.Key}} md5 {{$j.Password}}
{{- end}}
{{- end}}
exit'
`

const ospfDeleteTemplate = `'configure terminal
router ospf
{{range $m, $n := .NetworkCmd}}
no network {{$n.Network}} area {{$n.AreaId}}
{{- end}}
{{range $k, $v := .AreaCmd}}
{{if eq $v.Type "Stub"}}no area {{$v.Id}} stub{{end}}
{{if eq $v.Auth "Plaintext" "MD5"}}no area {{$v.Id}} authentication{{end}}
{{- end}}
{{range $i, $j := .IfaceCmd}}
interface {{$j.Name}}
{{if eq $j.Auth "Plaintext"}}
no ip ospf authentication
no ip ospf authentication-key
{{else if eq $j.Auth "MD5"}}
no ip ospf authentication
no ip ospf message-digest-key {{$j.Key}}
{{- end}}
{{- end}}
exit'
`

type IfaceAttrs struct {
	Name     string
	Auth     string
	Key      string
	Password string
}
type NetworkAttrs struct {
	Network string
	AreaId  string
}
type AreaAttrs struct {
	Id   string
	Auth string
	Type string
}

type VtyshOspfCmd struct {
	RouterIdCmd string
	IfaceCmd    map[string]IfaceAttrs
	NetworkCmd  map[string]NetworkAttrs
	AreaCmd     map[string]AreaAttrs
	isDelete    bool
}

func NewVtyshOspfCmd() *VtyshOspfCmd {
	cmd := &VtyshOspfCmd{
		RouterIdCmd: "",
		IfaceCmd:    make(map[string]IfaceAttrs),
		NetworkCmd:  make(map[string]NetworkAttrs),
		AreaCmd:     make(map[string]AreaAttrs),
		isDelete:    false,
	}

	return cmd
}

func (v *VtyshOspfCmd) SetRouteId(routeId string) *VtyshOspfCmd {
	v.RouterIdCmd = routeId

	return v
}

func (v *VtyshOspfCmd) SetInterface(ifname string, authType string, authParam string) *VtyshOspfCmd {
	attr := IfaceAttrs{}
	if authType == Plaintext {
		attr = IfaceAttrs{
			Name:     ifname,
			Auth:     authType,
			Key:      "",
			Password: authParam,
		}
	} else if authType == MD5 {
		tmp := strings.Split(authParam, "/")
		attr = IfaceAttrs{
			Name:     ifname,
			Auth:     authType,
			Key:      tmp[0],
			Password: tmp[1],
		}
	} else {
		attr = IfaceAttrs{
			Name:     ifname,
			Auth:     authType,
			Key:      "",
			Password: "",
		}
	}
	v.IfaceCmd[ifname] = attr

	return v
}
func (v *VtyshOspfCmd) DeleteInterface(ifname string) *VtyshOspfCmd {
	delete(v.IfaceCmd, ifname)

	return v
}

func (v *VtyshOspfCmd) SetNetwork(network string, areaId string) *VtyshOspfCmd {
	attrs := NetworkAttrs{
		Network: network,
		AreaId:  areaId,
	}
	v.NetworkCmd[network] = attrs

	return v
}
func (v *VtyshOspfCmd) DeleteNetwork(network string) *VtyshOspfCmd {
	delete(v.NetworkCmd, network)

	return v
}

func (v *VtyshOspfCmd) SetArea(areaId string, areaType string, authType string) *VtyshOspfCmd {
	attr := AreaAttrs{
		Id:   areaId,
		Type: areaType,
		Auth: authType,
	}
	v.AreaCmd[areaId] = attr

	return v
}
func (v *VtyshOspfCmd) DeleteArea(areaId string) *VtyshOspfCmd {
	delete(v.AreaCmd, areaId)

	return v
}

func (v *VtyshOspfCmd) SetDelete() *VtyshOspfCmd {
	v.isDelete = true

	return v
}

func (v *VtyshOspfCmd) Apply() error {
	var (
		tmpl *template.Template
		buf  bytes.Buffer
		err  error
	)

	if len(v.AreaCmd) == 0 && len(v.IfaceCmd) == 0 && len(v.NetworkCmd) == 0 {
		log.Debugf("ospf command is empty, no need invoke vtysh")
		return nil
	}
	if v.isDelete {
		if tmpl, err = template.New("deleteOspf").Parse(ospfDeleteTemplate); err != nil {
			return err
		}
		if err = tmpl.Execute(&buf, v); err != nil {
			return err
		}
	} else {
		if tmpl, err = template.New("addOspf").Parse(ospfAddTemplate); err != nil {
			return err
		}
		if err = tmpl.Execute(&buf, v); err != nil {
			return err
		}
	}

	bash := Bash{
		Command: fmt.Sprintf("vtysh -d ospfd -E -c %s", &buf),
	}

	if ret, out, _, err := bash.RunWithReturn(); ret != 0 || err != nil {
		return errors.Errorf("ospf command error: %+v", out)
	}

	return nil
}
