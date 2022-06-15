package utils

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"
)

const (
	SSHD_CONFIG_FILE      = "/etc/ssh/sshd_config"
	SSHD_CONFIG_FILE_TEMP = "/home/vyos/sshd_config"
	SSHD_TEMPLATE_FILE    = "template/sshd_tmpl"
	SSH_KEYS_PATH         = "/home/vyos/.ssh/authorized_keys"
)

type SshdInfo struct {
	Port          int
	ListenAddress string
	Keys          []string
}

func NewSshServer() *SshdInfo {
	sshAttr := SshdInfo{
		Port:          22,
		ListenAddress: "0.0.0.0",
	}
	return &sshAttr
}

func (s *SshdInfo) SetPorts(port int) *SshdInfo {
	if port > 0 {
		s.Port = port
	}

	return s
}

func (s *SshdInfo) SetListen(address string) *SshdInfo {
	if address != "" {
		s.ListenAddress = address
	}

	return s
}

func (s *SshdInfo) SetKeys(pub_key string) *SshdInfo {
	if pub_key != "" {
		s.Keys = append(s.Keys, pub_key)
	}

	return s
}

func (s *SshdInfo) ConfigService() error {
	var (
		buf  bytes.Buffer
		tmpl *template.Template
		err  error
	)

	if tmpl, err = template.New("ssh.conf").Parse(sshdTemplate); err != nil {
		return err
	}
	if err = tmpl.Execute(&buf, s); err != nil {
		return err
	}
	if err = ioutil.WriteFile(SSHD_CONFIG_FILE_TEMP, buf.Bytes(), 0664); err != nil {
		return err
	}
	bash := Bash{
		Command: fmt.Sprintf("mv %s %s", SSHD_CONFIG_FILE_TEMP, SSHD_CONFIG_FILE),
		Sudo:    true,
	}
	bash.Run()

	if len(s.Keys) != 0 {
		keys_str := strings.Join(s.Keys, "\n")
		file, err := CreateFileIfNotExists(SSH_KEYS_PATH, os.O_WRONLY|os.O_TRUNC, 0660)
		if err != nil {
			return err
		}
		defer file.Close()

		if _, err := file.WriteString(keys_str); err != nil {
			return err
		}
	}

	s.RestareServer()

	return nil
}

func (s *SshdInfo) RestareServer() error {
	bash := Bash{
		Command: "/etc/init.d/ssh restart",
		Sudo:    true,
	}

	return bash.Run()
}

func (s *SshdInfo) StopService() error {
	bash := Bash{
		Command: "/etc/init.d/ssh stop",
		Sudo:    true,
	}

	return bash.Run()
}
