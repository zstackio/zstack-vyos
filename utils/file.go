package utils

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
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

// ！！！ it will delete the directory, use with caution ！
func DeleteAllFiles(filePath string) error {
	if err := os.RemoveAll(filePath); err != nil {
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

// ReadLastNLine 读取文件的最后n行, 换行符号为LF/RF时有效, 返回数组为倒序
func ReadLastNLine(path string, n int) []string {
	fileHandle, err := os.Open(path)
	if err != nil {
		return append(make([]string, 0), "Cannot open file")
	}
	defer fileHandle.Close()

	var lines []string
	var line = ""
	var cursor int64 = 0
	stat, _ := fileHandle.Stat()
	filesize := stat.Size()
	for {
		cursor -= 1
		fileHandle.Seek(cursor, io.SeekEnd)
		char := make([]byte, 1)
		fileHandle.Read(char)
		if cursor != -1 && (char[0] == 10 || char[0] == 13) { // stop if we find a line (RF 10 LF 13)
			n -= 1
			lines = append(lines, line)
			line = ""
			if n == 0 {
				break
			}
			continue
		}
		line = fmt.Sprintf("%s%s", string(char), line) // there is more efficient way
		if cursor == -filesize {                       // stop if we are at the begining
			break
		}
	}
	return lines
}
