package utils

import (
	"bufio"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

func MkdirForFile(filepath string, perm os.FileMode) error {
	dir := path.Dir(filepath)
	return os.MkdirAll(dir, perm)
}

func CreateFileIfNotExists(filePath string, flag int, perm os.FileMode) (*os.File, error) {
	if err := MkdirForFile(filePath, 0666); err != nil {
		return nil, err
	}

	if ok, err := PathExists(filePath); err != nil {
		return nil, err
	} else if !ok {
		return os.OpenFile(filePath, os.O_CREATE|flag, perm)
	}

	return os.OpenFile(filePath, flag, perm)
}

func DeleteFile(filePath string) error {
	if err := os.Remove(filePath); err != nil {
		return err
	}
	return nil
}

func PathExists(filepath string) (bool, error) {
	_, err := os.Stat(filepath)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	} else {
		return true, nil
	}
}

func SudoMoveFile(oldpath, newpath string) error {
	return exec.Command("sudo", "/bin/mv", "-f", oldpath, newpath).Run()
}

func SetFileOwner(fpath, owner, group string) error {
	return exec.Command("sudo", "/bin/chown", fmt.Sprintf("%s:%s", owner, group), fpath).Run()
}

func SetFolderOwner(folderPath, owner, group string) error {
	return exec.Command("sudo", "/bin/chown", "-R", fmt.Sprintf("%s:%s", owner, group), folderPath).Run()
}

func Truncate(name string, size int64) error {
	return os.Truncate(name, size)
}

// io.Copy: The target file cannot be overwritten, if the target file is longer than the source file
// modify to ioutil.WriteFile
func CopyFile(srcFile, destFile string) error {
	input, err := ioutil.ReadFile(srcFile)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(destFile, input, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func ReadLine(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Errorf("file: %s open failed, because: %s", filePath, err)
		return "", err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Errorf("file: %s read failed, because: %s", filePath, err)
		return "", err
	}

	return line, nil
}

func ReadPid(pidPath string) (int, error) {
	pid, err := ReadLine(pidPath)
	if err != nil {
		return 0, err
	}

	pid = strings.TrimSpace(pid)
	log.Debugf("haproxy pid: %s", pid)
	return strconv.Atoi(pid)
}

// WriteFile 写一些需要root权限的文件使用，zvr进程使用vyos用户执行，无法直接调用 syscall
func WriteFile(path string, context string) error {
	_, fileName := filepath.Split(path)
	tmpFile, err := ioutil.TempFile("", fileName)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write([]byte(context))
	if err != nil {
		return err
	}

	if err = SudoMoveFile(tmpFile.Name(), path); err != nil {
		return err
	}

	return nil
}

func SudoRmFile(path string) error {
	return exec.Command("sudo", "/bin/rm", "-f", path).Run()
}
