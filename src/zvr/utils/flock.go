package utils

import (
	"fmt"
	"os"
	"syscall"
)

// Filelock defines an file lock (shared or exclusive).
type Filelock struct {
	file *os.File
}

func doLockFile(path string, mode int) (*Filelock, error) {
	// A shared or exclusive lock can be placed on a file regardless
	// of the mode in which the file was opened.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		return nil, fmt.Errorf("open %s: %s", path, err)
	}

	err = syscall.Flock(int(file.Fd()), mode)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("lock %s: %s", path, err)
	}

	return &Filelock{file}, nil
}

// LockFileShar imposes a share lock on a file
func LockFileShar(path string) (*Filelock, error) {
	return doLockFile(path, syscall.LOCK_SH)
}

// LockFileExcl locks a file exclusively.
func LockFileExcl(path string) (*Filelock, error) {
	return doLockFile(path, syscall.LOCK_EX)
}

// Unlock unlocks a lock holding by current process.
func (lck *Filelock) Unlock() error {
	file := lck.file
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	file.Close()
	os.Remove(file.Name())
	return err
}
