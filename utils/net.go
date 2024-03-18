package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	ZSTACK_ROUTE_PROTO            = "zstack"
	ZSTACK_ROUTE_PROTO_IDENTIFFER = "201"
	ZVR_ROUTE_PROTO               = "zvr"
	ZVR_ROUTE_PROTO_IDENTIFFER    = 202
)

func NetmaskToCIDR(netmask string) (int, error) {
	if strings.Contains(netmask, ".") {
		ipv4Mask := net.IPMask(net.ParseIP(netmask).To4())
		return calculateMaskLength(ipv4Mask), nil
	} else {
		ipv6Mask := net.IPMask(net.ParseIP(netmask).To16())
		return calculateMaskLength(ipv6Mask), nil
	}
}

func calculateMaskLength(mask net.IPMask) int {
	maskBytes := []byte(mask)
	length := 0

	for _, byteValue := range maskBytes {
		for i := 7; i >= 0; i-- {
			if (byteValue>>i)&1 == 1 {
				length++
			}
		}
	}

	return length
}

func GetNetworkNumber(ip, netmask string) (string, error) {
	ips := strings.Split(ip, ".")
	masks := strings.Split(netmask, ".")

	ipInByte := make([]interface{}, 4)
	for i := 0; i < len(ips); i++ {
		p, err := strconv.ParseUint(ips[i], 10, 32)
		if err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("unable to get network number[ip:%v, netmask:%v]", ip, netmask))
		}
		m, err := strconv.ParseUint(masks[i], 10, 32)
		PanicOnError(err)
		if err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("unable to get network number[ip:%v, netmask:%v]", ip, netmask))
		}
		ipInByte[i] = p & m
	}

	cidr, err := NetmaskToCIDR(netmask)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("unable to get network number[ip:%v, netmask:%v]", ip, netmask))
	}

	return fmt.Sprintf("%v.%v.%v.%v/%v", ipInByte[0], ipInByte[1], ipInByte[2], ipInByte[3], cidr), nil
}

type Nic struct {
	Name         string
	Mac          string
	Ip           string
	Ip6          string
	Gateway      string
	Gateway6     string
	IsDefault    bool
	Catatory     string
	Netmask      string
	PrefixLength int
}

func (nic Nic) String() string {
	s, _ := json.Marshal(nic)
	return string(s)
}

func GetAllNics() (map[string]Nic, error) {
	const ROOT = "/sys/class/net"

	files, err := ioutil.ReadDir(ROOT)
	if err != nil {
		return nil, err
	}

	nics := make(map[string]Nic)
	for _, f := range files {
		if f.IsDir() || f.Name() == "lo" || strings.Contains(f.Name(), "ifb") {
			continue
		}

		if f.Name() == "gre0" || f.Name() == "pimreg" {
			continue
		}

		macfile := filepath.Join(ROOT, f.Name(), "address")
		mac, err := ioutil.ReadFile(macfile)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("unable to read the mac file[%s]", macfile))
		}
		nics[f.Name()] = Nic{
			Name: strings.TrimSpace(f.Name()),
			Mac:  strings.TrimSpace(string(mac)),
		}
	}

	return nics, nil
}

func GetNicNameByMac(mac string) (string, error) {
	nics, err := GetAllNics()
	if err != nil {
		return "", err
	}

	for _, nic := range nics {
		if nic.Mac == mac {
			/* for vlan sub interface, nic.name is eth1.100 */
			name := strings.Split(nic.Name, ".")
			return name[0], nil
		}
	}

	return "", fmt.Errorf("cannot find any nic with the mac[%s]", mac)
}

func GetMacByNicName(nicName string) (string, error) {
	nics, err := GetAllNics()
	if err != nil {
		return "", err
	}

	for _, nic := range nics {
		if nic.Name == nicName {
			return nic.Mac, nil
		}
	}

	return "", fmt.Errorf("cannot find any mac with the nicName[%s]", nicName)
}

func GetNicNameByIp(ip string) (string, error) {
	bash := Bash{
		Command: fmt.Sprintf("ip addr | grep -w %s", ip),
	}
	ret, o, _, err := bash.RunWithReturn()
	if err != nil {
		return "", err
	}
	if ret != 0 {
		return "", errors.New(fmt.Sprintf("no nic with the IP[%s] found in the system", ip))
	}

	o = strings.TrimSpace(o)
	os := strings.Split(o, " ")
	return os[len(os)-1], nil
}

func GetIpByNicName(nic string) (string, error) {
	bash := Bash{
		Command: fmt.Sprintf("ip -o -f inet addr show %s | awk '/scope global/ {print $4}'", nic),
	}
	ret, o, _, err := bash.RunWithReturn()
	if err != nil {
		return "", err
	}
	if ret != 0 {
		return "", errors.New(fmt.Sprintf("no ip with the nic[%s] found in the system", nic))
	}

	o = strings.TrimSpace(o)
	os := strings.Split(o, "/")
	return os[0], nil
}

func GetIpFromUrl(url string) (string, error) {
	ip := strings.Split(strings.Split(url, "/")[2], ":")[0]
	return ip, nil
}

func CheckIpDuplicate(nicname, ip string) bool {
	b := Bash{Command: fmt.Sprintf("sudo arping -D -w 2 -c 1 -I %s %s", nicname, ip)}
	err := b.Run()
	return err != nil
}

func CheckZStackRouteExists(ip string) bool {
	bash := Bash{
		Command: fmt.Sprintf("ip r list %s/32 proto zstack", ip),
	}
	_, o, _, _ := bash.RunWithReturn()
	if o == "" {
		return false
	}
	return true
}

func DeleteRouteIfExists(ip string) error {
	if CheckZStackRouteExists(ip) == true {
		bash := Bash{
			Command: fmt.Sprintf("sudo ip route del %s/32", ip),
		}
		_, _, _, err := bash.RunWithReturn()
		if err != nil {
			return err
		}
	}

	return nil
}

func SetZStackRoute(ip string, nic string, gw string) error {
	SetZStackRouteProtoIdentifier()
	SetZvrRouteProtoIdentifier()
	DeleteRouteIfExists(ip)

	var bash Bash
	if gw == "" {
		bash = Bash{
			Command: fmt.Sprintf("sudo ip route add %s/32 dev %s proto %s", ip, nic, ZSTACK_ROUTE_PROTO),
		}
	} else {
		bash = Bash{
			Command: fmt.Sprintf("sudo ip route add %s/32 via %s dev %s proto %s", ip, gw, nic, ZSTACK_ROUTE_PROTO),
		}
	}

	ret, _, _, err := bash.RunWithReturn()
	if err != nil {
		return err
	}
	// NOTE(WeiW): It will return 2 if exists
	if ret != 0 && ret != 2 {
		return errors.New(fmt.Sprintf("add route to %s/32 via %s dev %s failed", ip, gw, nic))
	}

	return nil
}

func GetNicForRoute(ip string) string {
	bash := Bash{
		Command: fmt.Sprintf("ip -o r get %s | awk '{print $3}'", ip),
	}
	_, o, _, err := bash.RunWithReturn()
	PanicOnError(err)
	return o
}

func RemoveZStackRoute(ip string) error {
	SetZStackRouteProtoIdentifier()
	// DeleteRouteIfExists: delete only when the route exists and the type is ZSTACK_ROUTE_PROTO
	if err := DeleteRouteIfExists(ip); err != nil {
		return err
	}

	return nil
}

func SetZStackRouteProtoIdentifier() {
	bash := Bash{
		Command: "grep zstack /etc/iproute2/rt_protos",
	}
	check, _, _, _ := bash.RunWithReturn()

	if check != 0 {
		log.Debugf("no route proto zstack in /etc/iproute2/rt_protos")
		bash = Bash{
			Command: fmt.Sprintf("sudo bash -c \"echo -e '\n\n# Used by zstack\n%s     zstack' >> /etc/iproute2/rt_protos\"", ZSTACK_ROUTE_PROTO_IDENTIFFER),
		}
		bash.Run()
	}
}

func SetZvrRouteProtoIdentifier() {
	bash := Bash{
		Command: "grep zvr /etc/iproute2/rt_protos",
	}
	if check, _, _, _ := bash.RunWithReturn(); check != 0 {
		log.Debugf("no route proto zvr in /etc/iproute2/rt_protos")
		bash = Bash{
			Command: fmt.Sprintf("bash -c \"echo '%d     zvr' >> /etc/iproute2/rt_protos\"", ZVR_ROUTE_PROTO_IDENTIFFER),
			Sudo:    true,
		}
		bash.Run()
	}
}

func GetNicNumber(nic string) (int, error) {
	num, err := strconv.ParseInt(strings.Split(nic, "eth")[1], 10, 64)
	if err != nil {
		return -1, err
	}
	return int(num), nil
}

func CheckMgmtCidrContainsIp(ip string, mgmtNic map[string]interface{}) bool {
	maskCidr, err := NetmaskToCIDR(mgmtNic["netmask"].(string))
	PanicOnError(err)
	_, mgmtNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", mgmtNic["ip"], maskCidr))
	PanicOnError(err)

	return mgmtNet.Contains(net.ParseIP(ip))
}

func GetPrivteInterface() []string {
	bash := Bash{
		Command: fmt.Sprintf("sudo ip link | grep -B 2 'category:Private' | grep '<BROADCAST,MULTICAST' | awk -F ':' '{print $2}'"),
	}
	ret, o, _, err := bash.RunWithReturn()
	if err != nil {
		return nil
	}
	if ret != 0 {
		return nil
	}

	lines := strings.Split(o, "\n")
	var nics []string
	for _, name := range lines {
		name = strings.Trim(name, " ")
		if name != "" {
			nics = append(nics, name)
		}
	}

	if len(nics) == 0 {
		return nil
	}

	return nics
}

func GetUpperIp(cidr net.IPNet) net.IP {
	ip := cidr.IP
	mask := cidr.Mask
	n := len(ip)
	if n != len(mask) {
		return nil
	}
	out := make(net.IP, n)
	for i := 0; i < n; i++ {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

/* this only for ipv4 */
func GetBroadcastIpFromNetwork(ip, netmask string) string {
	var brAddress []string
	ips := strings.Split(ip, ".")
	masks := strings.Split(netmask, ".")

	for i := 0; i < 4; i++ {
		ipByte, err := strconv.Atoi(ips[i])
		PanicOnError(err)
		maskByte, err := strconv.Atoi(masks[i])
		PanicOnError(err)
		ipByte = ipByte & maskByte
		maskByte = maskByte ^ 0xFF

		brAddress = append(brAddress, fmt.Sprintf("%d", (byte)(ipByte^maskByte)))
	}

	return strings.Join(brAddress, ".")
}

func GetNexthop(dst string) (string, error) {
	/* $ ip r get 10.86.4.0/23
	   10.86.4.0 via 192.168.100.1 dev eth1  src 192.168.100.129
	       cache
	   $ ip r get 192.168.250.0/24
	   broadcast 192.168.250.0 dev eth0  src 192.168.250.14
	       cache <local,brd>
	*/
	bash := Bash{
		Command: fmt.Sprintf("ip r get %s | grep via | awk '{print $3}'", dst),
	}
	ret, o, e, err := bash.RunWithReturn()
	if err != nil {
		return "", err
	}
	if ret != 0 {
		return "", fmt.Errorf("get nexthop for %s failed, ret = %d, error:%s", dst, ret, e)
	}

	return strings.TrimSpace(o), nil
}

func AddRoute(dst, nexthop string) error {
	bash := Bash{
		Command: fmt.Sprintf("sudo ip route add %s via %s", dst, nexthop),
	}
	ret, _, e, err := bash.RunWithReturn()
	if err != nil {
		if strings.Contains(e, "File exists") {
			log.Debugf("route is exists, skip err")
			return nil
		}
		return err
	}
	if ret != 0 {
		return fmt.Errorf("add route %s nexthop %s failed, ret = %d, error:%s", dst, nexthop, ret, e)
	}

	return nil
}

func FlushNicRoute(nic string) error {
	bash := Bash{
		Command: fmt.Sprintf("sudo ip route flush dev %s", nic),
	}
	ret, _, _, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return nil
	}

	return err
}

func DelIp6DefaultRoute() error {
	bash := Bash{
		Command: fmt.Sprintf("ip -6 r | grep default | awk '{print $3}'"),
	}
	ret, oldGw6, _, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return nil
	}

	bash = Bash{
		Command: fmt.Sprintf(fmt.Sprintf("sudo ip -6 route del default via %s", oldGw6)),
	}
	_, _, _, err = bash.RunWithReturn()

	return err
}

func AddIp6DefaultRoute(gw6, dev string) {
	/* default ip6 route
	   # ip -6 r | grep default
	   default via caca::1 dev eth1  metric 1024 */

	oldGw6 := ""
	bash := Bash{
		Command: fmt.Sprintf("ip -6 r | grep default | awk '{print $3}'"),
	}
	ret, o, _, err := bash.RunWithReturn()
	if err == nil && ret == 0 {
		oldGw6 = o
	}

	var cmds []string
	if oldGw6 != "" {
		cmds = append(cmds, fmt.Sprintf("sudo ip -6 route del default via %s", oldGw6))
	}
	cmds = append(cmds, fmt.Sprintf("sudo ip -6 route add default via %s dev %s", gw6, dev))
	bash = Bash{
		Command: strings.Join(cmds, ";"),
	}
	_, _, _, err = bash.RunWithReturn()
	PanicOnError(err)
}

func DelIp4DefaultRoute() error {
	bash := Bash{
		Command: fmt.Sprintf("ip -4 r | grep default | awk '{print $3}'"),
	}
	ret, oldGw4, _, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return nil
	}

	bash = Bash{
		Command: fmt.Sprintf(fmt.Sprintf("sudo ip -4 route del default via %s", oldGw4)),
	}
	_, _, _, err = bash.RunWithReturn()

	return err
}

func AddIp4DefaultRoute(gw4, dev string) {
	oldGw4 := ""
	bash := Bash{
		Command: fmt.Sprintf("ip -4 r | grep default | awk '{print $3}'"),
	}
	ret, o, _, err := bash.RunWithReturn()
	if err == nil && ret == 0 {
		oldGw4 = o
	}

	var cmds []string
	if oldGw4 != "" {
		cmds = append(cmds, fmt.Sprintf("sudo ip -4 route del default via %s", oldGw4))
	}
	cmds = append(cmds, fmt.Sprintf("sudo ip -4 route add default via %s dev %s", gw4, dev))
	bash = Bash{
		Command: strings.Join(cmds, ";"),
	}
	_, _, _, err = bash.RunWithReturn()
	PanicOnError(err)
}

func IsIpv4Address(address string) bool {
	parsedIP := net.ParseIP(address)
	if parsedIP != nil && parsedIP.To4() != nil {
		return true
	}

	return false
}

func IsMgtNic(name string) bool {
	return name == "eth0"
}
