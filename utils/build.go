package utils

import (
	"bytes"
	"html/template"
	"os"
	"strings"
)

const infoStr = `version: {{.Version}} ({{.ModuleName}}: {{.GitInfo}})
build user: {{.User}}
build time: {{.Time}}
target platform: {{.Platform}}
go version: {{.GoVersion}}
`

var (
	CommandVersion bool

	Version    string
	ModuleName string
	GitInfo    string
	User       string
	Time       string
	Platform   string
	GoVersion  string
)

func getInfoMap() map[string]string {
	return map[string]string{
		"Version":    Version,
		"ModuleName": ModuleName,
		"GitInfo":    GitInfo,
		"User":       User,
		"Time":       Time,
		"Platform":   Platform,
		"GoVersion":  GoVersion,
	}
}

func PrintBuildInfo() {
	tmpl, _ := template.New("buildInfo").Parse(infoStr)

	_ = tmpl.Execute(os.Stdout, getInfoMap())
}

func GetBuildInfo() string {
	tmpl, _ := template.New("buildInfo").Parse(strings.ReplaceAll(infoStr, "\n", "\\n"))

	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, getInfoMap())
	return buf.String()
}
