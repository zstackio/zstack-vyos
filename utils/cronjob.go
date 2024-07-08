package utils

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	log "github.com/sirupsen/logrus"
)

var (
	CROND_CONFIG_FILE      = "/etc/cron.d/zstack_cronjob"
)

func getCrondConfigFileTemp() string {
	return filepath.Join(GetZvrRootPath(), "zstack_cronjob")
}

func getCrondJsonFile() string {
	return filepath.Join(GetZvrRootPath(), ".zstack_config/cronjob")
}

type CronjobMap map[int]*Cronjob

type Cronjob struct {
	TaskId      int
	ExecCommand string
	FieldMinute string
	FieldHour   string
	FieldDay    string
	FieldMonth  string
	FieldWeek   string
	Description string
	isDelete    bool
}

const CrondTemplate = `#
# Create by Zstack, Do Not Modify It
#
SHELL=/bin/bash
{{range $i, $v := .}}
# {{$v.Description}}
{{$v.FieldMinute}} {{$v.FieldHour}} {{$v.FieldDay}} {{$v.FieldMonth}} {{$v.FieldWeek}} root {{$v.ExecCommand}}
{{end}}`

func NewCronjob() *Cronjob {
	newCrontab := Cronjob{
		TaskId:      0,
		ExecCommand: "",
		FieldMinute: "*",
		FieldHour:   "*",
		FieldDay:    "*",
		FieldMonth:  "*",
		FieldWeek:   "*",
		Description: "zstack cronjob",
		isDelete:    false,
	}

	return &newCrontab
}

func (c *Cronjob) SetId(id int) *Cronjob {
	c.TaskId = id

	return c
}

func (c *Cronjob) SetCommand(cmd string) *Cronjob {
	c.ExecCommand = cmd

	return c
}
func (c *Cronjob) SetMinute(fieldMinute string) *Cronjob {
	if fieldMinute != "" {
		c.FieldMinute = fieldMinute
	}

	return c
}
func (c *Cronjob) SetHour(fieldHour string) *Cronjob {
	if fieldHour != "" {
		c.FieldHour = fieldHour
	}

	return c
}
func (c *Cronjob) SetDay(fieldDay string) *Cronjob {
	if fieldDay != "" {
		c.FieldDay = fieldDay
	}

	return c
}
func (c *Cronjob) SetMonth(fieldMonth string) *Cronjob {
	if fieldMonth != "" {
		c.FieldMonth = fieldMonth
	}

	return c
}
func (c *Cronjob) SetWeek(fieldWeek string) *Cronjob {
	if fieldWeek != "" {
		c.FieldWeek = fieldWeek
	}

	return c
}
func (c *Cronjob) SetDescription(note string) *Cronjob {
	c.Description = note

	return c
}
func (c *Cronjob) SetDelete() *Cronjob {
	c.isDelete = true

	return c
}

func (c CronjobMap) ConfigService() error {
	var (
		buf  bytes.Buffer
		tmpl *template.Template
		err  error
	)
	cronjobAttrs := make(CronjobMap)

	if err := JsonLoadConfig(getCrondJsonFile(), &cronjobAttrs); err != nil {
		/* ignore the error */
		log.Debugf("local cronjob failed: %v", err)
	}

	i := 0
	newCronjobAttrs := make(CronjobMap)
	for k, v := range c {
		if v.isDelete {
			log.Debugf("cronjob[%d] will be delete", k)
			delete(cronjobAttrs, k)
		} else {
			if v.ExecCommand == "" || v.TaskId == 0 {
				log.Debugf("cronjob's exec cmd or task id can not be empty")
				continue
			}
			log.Debugf("cronjob[%d] will be add", k)
			newCronjobAttrs[i] =v
			i++
		}
	}
	if tmpl, err = template.New("crond.conf").Parse(CrondTemplate); err != nil {
		log.Debugf("CrondTemplate parse failed: %v", err)
		return err
	}
	if err = tmpl.Execute(&buf, newCronjobAttrs); err != nil {
		log.Debugf("CrondTemplate Execute failed: %v", err)
		return err
	}
	if err = os.WriteFile(getCrondConfigFileTemp(), buf.Bytes(), 0664); err != nil {
		log.Debugf("CrondTemplate WriteFile failed: %v", err)
		return err
	}
	bash := Bash{
		Command: fmt.Sprintf("mv %s %s", getCrondConfigFileTemp(), CROND_CONFIG_FILE),
		Sudo:    true,
	}
	bash.Run()

	return JsonStoreConfig(getCrondJsonFile(), cronjobAttrs)
}

func GetNtpdCommand(operation string) string {
	var command string
	if IsVYOS() {
		command = fmt.Sprintf("/etc/init.d/ntp %s", operation)
	} else {
		command = fmt.Sprintf("systemctl %s ntpd", operation)
	}

	return command
}

func (c CronjobMap) RestartService() error {
	return ServiceOperation("crond", "restart")
}

func (c CronjobMap) StopService() error {
	return ServiceOperation("crond", "stop")
}
