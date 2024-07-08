package utils

import (
	"errors"
	"fmt"
	"path/filepath"
)

const (
	BLACKHOLE_ROUTE = "null0"
)

type ZebraRoute struct {
	Dst      string
	NextHop  string
	OutDev   string
	Distance int
	isDelete bool
}

func GetZebraJsonFile() string {
	return filepath.Join(GetZvrZsConfigPath(), "zebra.json")
}

func NewZebraRoute() *ZebraRoute {
	cmd := &ZebraRoute{
		Dst:      "",
		NextHop:  "",
		OutDev:   "",
		Distance: 0,
		isDelete: false,
	}

	return cmd
}

func (z *ZebraRoute) SetDst(dstCidr string) *ZebraRoute {
	z.Dst = dstCidr

	return z
}

func (z *ZebraRoute) SetDev(devName string) *ZebraRoute {
	z.OutDev = devName

	return z
}

//If the param is "null0", then zebra installs a blackhole route
func (z *ZebraRoute) SetNextHop(nexthop string) *ZebraRoute {
	z.NextHop = nexthop

	return z
}

func (z *ZebraRoute) SetDistance(distance int) *ZebraRoute {
	z.Distance = distance

	return z
}

func (z *ZebraRoute) SetDelete() *ZebraRoute {
	z.isDelete = true

	return z
}

func (z *ZebraRoute) Apply() error {
	var (
		cmd string
	)
	if z.Dst == "" {
		return errors.New("dst can not be empty")
	}

	if z.Distance != 0 && z.OutDev != "" {
		return errors.New("cannot set out device and distance at the same time")
	} else if z.Distance != 0 && z.OutDev == "" {
		cmd = fmt.Sprintf("ip route %s %s %d", z.Dst, z.NextHop, z.Distance)
	} else if z.Distance == 0 && z.OutDev != "" {
		cmd = fmt.Sprintf("ip route %s %s %s", z.Dst, z.NextHop, z.OutDev)
	} else {
		cmd = fmt.Sprintf("ip route %s %s", z.Dst, z.NextHop)
	}

	if z.isDelete {
		cmd = "no " + cmd
	}

	bash := Bash{
		Command: fmt.Sprintf("vtysh -c 'configure terminal' -c '%s'", cmd),
	}

	if _, _, _, err := bash.RunWithReturn(); err != nil {
		return err
	}
	return nil
}
