package utils

import (
	"bytes"
	"html/template"
	"io"
	"os"
	"runtime"
	"strings"
)

const infoStr = `version: {{.Version}} ({{.ModuleName}}: {{.GitInfo}})
build user: {{.User}}
build time: {{.Time}}
target platform: {{.Platform}}
go version: {{.GoVersion}}
`

var (
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

func InitBuildInfo(moduleName string, version string) {
	ModuleName = moduleName

	if len(version) != 0 {
		Version = version
	}

	if len(Platform) == 0 {
		Platform = runtime.GOOS + "/" + runtime.GOARCH
	}
}

func ShowVersionAndExit(w io.Writer) {
	tmpl, _ := template.New("buildInfo").Parse(infoStr)

	_ = tmpl.Execute(w, getInfoMap())
	os.Exit(0)
}

func GetBuildInfo() string {
	tmpl, _ := template.New("buildInfo").Parse(strings.ReplaceAll(infoStr, "\n", "\\n"))

	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, getInfoMap())
	return buf.String()
}
