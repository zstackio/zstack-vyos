package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"text/template"
)

var (
	configPath string
	config     Config
)

type (
	ProjectConfig struct {
		Dir       *string `json:"dir"`
		Installer *string `json:"installer"`
		Location  *string `json:"location"`
		Env       string  `json:"env"`
	}

	Config struct {
		Projects map[string]ProjectConfig `json:"projects"`
	}

	Project struct {
		name   string
		config ProjectConfig
	}
)

func NewProject(name string, config ProjectConfig) *Project {
	p := &Project{name: name, config: config}
	return p
}

func (project *Project) checkConfig() {
	if project.config.Dir == nil {
		panic(fmt.Errorf("missing parameter[dir] of the project[%s]", project.name))
	}
	if project.config.Installer == nil {
		panic(fmt.Errorf("missing parameter[installer] of the project[%s]", project.name))
	}
	if project.config.Location == nil {
		panic(fmt.Errorf("missing parameter[location] of the project[%s]", project.name))
	}
}

func (project *Project) build() {
	project.checkConfig()

	script := `#!/bin/bash
set -e

cwd=$(pwd)
tmpdir=$(mktemp -d)
targetdir="$tmpdir/target"
mkdir -p $targetdir

datatar="$targetdir/data.tar.gz"
targettar="$tmpdir/target.tar.gz"

tar czf $datatar -C $cwd/{{.Dir}} .
cp {{.Installer}} $targetdir

tar cf $targettar -C $targetdir/ .

cat >> $tmpdir/setup.sh <<'EOF'
#!/bin/bash
PATH=/bin:/usr/bin
line=$(wc -l $0 | awk '{print $1}')
line=$((line - 12))
tmpdir=$(mktemp -d)
rm -rf $tmpdir
mkdir -p $tmpdir
tail -n $line $0 | tar x -C $tmpdir
cd $tmpdir
{{.Env}} bash {{.InstallScript}} $@
ret=$?
rm -rf $tmpdir
exit $ret
EOF

mkdir -p $(dirname {{.BinaryPath}})
cat $tmpdir/setup.sh $targettar > {{.BinaryPath}}
chmod a+x {{.BinaryPath}}
rm -rf $tmpdir
`
	binaryPath := fmt.Sprintf("%s/%s.bin", *project.config.Location, project.name)
	context := map[string]string{
		"Dir":           *project.config.Dir,
		"Installer":     *project.config.Installer,
		"BinaryPath":    binaryPath,
		"InstallScript": path.Base(*project.config.Installer),
		"Env":           project.config.Env,
	}

	tmpl, err := template.New("script").Parse(script)
	if err != nil {
		panic(err)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, context)
	if err != nil {
		panic(err)
	}

	if out, err := exec.Command("sh", "-c", buf.String()).CombinedOutput(); err != nil {
		panic(fmt.Errorf("failed to execute script:\n%s\n%s\n%s", buf.String(), out, err))
	} else {
		fmt.Println(string(out))
	}

	fmt.Println(fmt.Sprintf("successfully built the project [%s] to %s", project.name, binaryPath))
}

func init() {
	flag.StringVar(&configPath, "conf", "", "path to the configuration file")
	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		fmt.Printf("unknown options %v\n", flag.Args())
		os.Exit(1)
	}

	if configPath == "" {
		flag.Usage()
		fmt.Printf("option [-conf] is required and cannot be an empty string\n")
		os.Exit(1)
	}
}

func build() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()

	f, err := ioutil.ReadFile(configPath)
	if err != nil {
		panic(fmt.Errorf("unable to read the config file[%s], %s", configPath, err))
	}

	config := Config{}
	err = json.Unmarshal(f, &config)
	if err != nil {
		panic(fmt.Errorf("unable to JSON unmarshal the config file[%s], %s", configPath, err))
	}

	for key, value := range config.Projects {
		p := NewProject(key, value)
		p.build()
	}
}

func main() {
	build()
}
