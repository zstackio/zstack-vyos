package utils

import (
	"testing"
	"fmt"
)

func TestNetmaskToCIDR(t *testing.T) {
	cidr, err := NetmaskToCIDR("255.255.255.0")
	Assert(cidr == 24, fmt.Sprint(cidr))
	Assert(err == nil, "")

	cidr, _ = NetmaskToCIDR("255.255.252.0")
	Assert(cidr == 22, fmt.Sprint(cidr))

	cidr, _ = NetmaskToCIDR("255.254.0.0")
	Assert(cidr == 15, fmt.Sprint(cidr))

	cidr, _ = NetmaskToCIDR("0.0.0.0")
	Assert(cidr == 0, fmt.Sprint(cidr))

	cidr, _ = NetmaskToCIDR("254.0.0.0")
	Assert(cidr == 7, fmt.Sprint(cidr))

	cidr, _ = NetmaskToCIDR("255.255.255.255")
	Assert(cidr == 32, fmt.Sprint(cidr))
}

func TestGetNetworkNumber(t *testing.T) {
	network, err := GetNetworkNumber("172.20.14.17", "255.255.0.0")
	Assert(err == nil, "error")
	Assert("172.20.0.0/16" == network, network)

	network, err = GetNetworkNumber("172.20.14.16", "255.255.0.0")
	Assert(err == nil, "error")
	Assert("172.20.0.0/16" == network, network)

	network, err = GetNetworkNumber("172.20.14.16", "255.255.255.0")
	Assert(err == nil, "error")
	Assert("172.20.14.0/24" == network, network)
}

func TestGetAllNics(t *testing.T) {
	nics, err := GetAllNics()
	Assert(err == nil, "error")
	fmt.Println(nics)
}
