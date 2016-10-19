package utils

import (
	"os"
	"path"
)

func CreateFileIfNotExists(filePath string, flag int, perm os.FileMode) (*os.File, error)  {
	dir := path.Dir(filePath)
	if err := os.MkdirAll(dir, 0666); err != nil {
		return nil, err
	}

	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return os.OpenFile(filePath, os.O_CREATE | flag, perm)
	} else if err != nil {
		return nil, err
	}

	return os.OpenFile(filePath, flag, perm)
}
