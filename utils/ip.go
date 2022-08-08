package utils

import (
	"fmt"
	"math/big"
	"net"
)

func InetNtoA(ip int64) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func InetAtoN(ip string) int64 {
	ret := big.NewInt(0)
	ret.SetBytes(net.ParseIP(ip).To4())
	return ret.Int64()
}

// GetUnicastIPRange get valid unicast ip address range.
// for example: ip="10.0.0.0", mask="255.255.255.0, return "10.0.0.1", "10.0.0.254"
// Returns "", "" if no valid unicast address is available
func GetUnicastIPRange(ip, mask string) (first, last string, firstI, lastI uint32) {
	ipInt := uint32(InetAtoN(ip))
	maskInt := uint32(InetAtoN(mask))
	ipInt = ipInt & maskInt

	mReverse := ^maskInt
	if mReverse <= 1 {
		return "", "", 0, 0
	}

	return InetNtoA(int64(ipInt + 1)), InetNtoA(int64(ipInt + mReverse - 1)), ipInt + 1, ipInt + mReverse - 1
}
