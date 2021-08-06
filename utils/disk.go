package utils

import (
	"golang.org/x/sys/unix"
)

type DiskStatus struct {
	All   uint64 // total data blocks in filesystem
	Free  uint64 // free blocks in filesystem
	Avail uint64 // free blocks available to unprivileged user
}

func DiskUsage(path string) (*DiskStatus, error) {
	stat := &unix.Statfs_t{}
	if err := unix.Statfs(path, stat); err != nil {
		return nil, err
	}

	return &DiskStatus{
		All:   stat.Blocks * uint64(stat.Bsize),
		Free:  stat.Bfree * uint64(stat.Bsize),
		Avail: stat.Bavail * uint64(stat.Bsize),
	}, nil
}
