package utils

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"text/template"

	log "github.com/Sirupsen/logrus"
)

const (
	CROND_CONFIG_FILE      = "/etc/cron.d/zstack_cronjob"
	CROND_CONFIG_FILE_TEMP = "/home/vyos/zstack_cronjob"
	CROND_JSON_FILE        = "/home/vyos/zvr/.zstack_config/cronjob"
)

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

	if err := JsonLoadConfig(CROND_JSON_FILE, &cronjobAttrs); err != nil {
		return err
	}

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
			cronjobAttrs[k] = v
		}
	}
	if tmpl, err = template.New("crond.conf").Parse(CrondTemplate); err != nil {
		return err
	}
	if err = tmpl.Execute(&buf, cronjobAttrs); err != nil {
		return err
	}
	if err = ioutil.WriteFile(CROND_CONFIG_FILE_TEMP, buf.Bytes(), 0664); err != nil {
		return err
	}
	bash := Bash{
		Command: fmt.Sprintf("mv %s %s", CROND_CONFIG_FILE_TEMP, CROND_CONFIG_FILE),
		Sudo:    true,
	}
	bash.Run()

	return JsonStoreConfig(CROND_JSON_FILE, cronjobAttrs)
}

func (c CronjobMap) RestartService() error {
	bash := Bash{
		Command: "/etc/init.d/cron restart",
		Sudo:    true,
	}

	return bash.Run()
}

func (c CronjobMap) StopService() error {
	bash := Bash{
		Command: "/etc/init.d/cron stop",
		Sudo:    true,
	}

	return bash.Run()
}
