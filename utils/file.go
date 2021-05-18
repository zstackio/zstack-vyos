package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"io"
)

func MkdirForFile(filepath string, perm os.FileMode) error {
	dir := path.Dir(filepath)
	return os.MkdirAll(dir, perm)
}

func CreateFileIfNotExists(filePath string, flag int, perm os.FileMode) (*os.File, error)  {
	if err := MkdirForFile(filePath, 0666); err != nil {
		return nil, err
	}

	if ok, err:= PathExists(filePath); err != nil {
		return nil, err
	} else if !ok {
		return os.OpenFile(filePath, os.O_CREATE | flag, perm)
	}

	return os.OpenFile(filePath, flag, perm)
}

func DeleteFile(filePath string) error{
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
	} else  {
		return true, nil
	}
}

func SudoMoveFile(oldpath, newpath string) error {
	return exec.Command("sudo", "/bin/mv", "-f", oldpath, newpath).Run()
}

func SetFileOwner(fpath, owner, group string) error {
	return exec.Command("sudo", "/bin/chown", fmt.Sprintf("%s:%s", owner, group), fpath).Run()
}

func Truncate(name string, size int64) error {
	return os.Truncate(name, size)
}

func CopyFile(srcFile,destFile string)(int64,error){
    srcfile,err := os.Open(srcFile)
    if err != nil{
        return 0,err
    }
    dstfile,err := os.OpenFile(destFile,os.O_WRONLY|os.O_CREATE,os.ModePerm)
    if err != nil{
        return 0,err
    }
    defer srcfile.Close()
    defer dstfile.Close()
    return io.Copy(dstfile,srcfile)
}
