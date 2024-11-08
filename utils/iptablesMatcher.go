package utils

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	IPTABLES_PROTO_TCP  = "tcp"
	IPTABLES_PROTO_UDP  = "udp"
	IPTABLES_PROTO_ICMP = "icmp"
	IPTABLES_PROTO_ESP  = "esp"
	IPTABLES_PROTO_AH   = "ah"
	IPTABLES_PROTO_OSPF = "ospf"
	IPTABLES_PROTO_PIMD = "pim"
	IPTABLES_PROTO_IGMP = "igmp"
	IPTABLES_PROTO_VRRP = "vrrp"
)

const (
	IPTABLES_STATE_NEW         = "NEW"
	IPTABLES_STATE_RELATED     = "RELATED"
	IPTABLES_STATE_ESTABLISHED = "ESTABLISHED"
	IPTABLES_STATE_INVALID     = "INVALID"
)

type IptablesMarkType int

const (
	IptablesMarkUnset IptablesMarkType = iota
	IptablesMarkMatch
	IptablesMarkNotMatch
)

type IpTableMatcher struct {
	chainName string

	proto                  string
	icmpType               string
	srcIp, dstIp           string
	srcIpRange, dstIpRange string

	srcPort, dstPort string
	states           []string
	comment          string
	inNic, outNic    string
	tcpFlags         []string
	mark             int
	markType         IptablesMarkType
	srcIpSet         string
	srcIpPortSet     string
	dstIpSet         string
	dstIpPortSet     string
	ipvs             bool
	ipvsVaddr        string
	ipvsVport        string
}

var icmpTypeToCode = map[string]string{
	"echo-reply":              "0",
	"echo-request":            "8",
	"destination-unreachable": "3",
	"source-quench":           "4",
	"redirect":                "5",
	"router-advertisement":    "9",
	"router-solicitation":     "10",
	"time-exceeded":           "11",
	"parameter-problem":       "12",
	"timestamp-request":       "13",
	"timestamp-reply":         "14",
	"address-mask-request":    "17",
	"address-mask-reply":      "18",
}

var icmpCodeToType = map[string]string{
	"0":  "echo-reply",
	"8":  "echo-request",
	"3":  "destination-unreachable",
	"4":  "source-quench",
	"5":  "redirect",
	"9":  "router-advertisement",
	"10": "router-solicitation",
	"11": "time-exceeded",
	"12": "parameter-problem",
	"13": "timestamp-request",
	"14": "timestamp-reply",
	"17": "address-mask-request",
	"18": "address-mask-reply",
}

func formatIcmpType(icmpType string) string {
	if v, ok := icmpTypeToCode[icmpType]; ok {
		return v
	} else {
		return icmpType
	}
}

func formatIcmpCode(icmpCode string) string {
	if v, ok := icmpCodeToType[icmpCode]; ok {
		return v
	} else {
		return icmpCode
	}
}

func (r *IpTableRule) SetChainName(chainName string) *IpTableRule {
	r.chainName = chainName
	return r
}

func (r *IpTableRule) SetProto(proto string) *IpTableRule {
	r.proto = proto
	return r
}

func (r *IpTableRule) SetIcmpType(icmpType string) *IpTableRule {
	r.icmpType = formatIcmpType(icmpType)
	return r
}

func (r *IpTableRule) SetSrcIp(srcIp string) *IpTableRule {
	r.srcIp = srcIp
	return r
}

func (r *IpTableRule) SetDstIp(dstIp string) *IpTableRule {
	if _, _, err := net.ParseCIDR(dstIp); err == nil {
		r.dstIp = dstIp
	}

	return r
}

func (r *IpTableRule) SetSrcIpRange(srcIpRange string) *IpTableRule {
	r.srcIpRange = srcIpRange
	return r
}

func (r *IpTableRule) SetDstIpRange(dstIpRange string) *IpTableRule {
	r.dstIpRange = dstIpRange
	return r
}

func (r *IpTableRule) SetSrcPort(srcPort string) *IpTableRule {
	r.srcPort = srcPort
	return r
}

func (r *IpTableRule) SetDstPort(dstPort string) *IpTableRule {
	r.dstPort = dstPort
	return r
}

func (r *IpTableRule) SetState(states []string) *IpTableRule {
	r.states = states
	return r
}

func (r *IpTableRule) setComment(comment string) *IpTableRule {
	r.comment = comment
	return r
}

func (r *IpTableRule) SetInNic(inNic string) *IpTableRule {
	r.inNic = inNic
	return r
}

func (r *IpTableRule) SetOutNic(outNic string) *IpTableRule {
	r.outNic = outNic
	return r
}

func (r *IpTableRule) SetTcpFlags(tcpFlags []string) *IpTableRule {
	r.tcpFlags = tcpFlags
	return r
}

func (r *IpTableRule) SetMark(mark int) *IpTableRule {
	r.mark = mark
	return r
}

func (r *IpTableRule) SetMarkType(markType IptablesMarkType) *IpTableRule {
	r.markType = markType
	return r
}

func (r *IpTableRule) SetSrcIpset(srcIpSet string) *IpTableRule {
	r.srcIpSet = srcIpSet
	return r
}

func (r *IpTableRule) SetSrcIpPortset(srcIpPortSet string) *IpTableRule {
	r.srcIpPortSet = srcIpPortSet
	return r
}

func (r *IpTableRule) SetDstIpset(dstIpSet string) *IpTableRule {
	r.dstIpSet = dstIpSet
	return r
}

func (r *IpTableRule) SetDstIpPortset(dstIpPortSet string) *IpTableRule {
	r.dstIpPortSet = dstIpPortSet
	return r
}

func (r *IpTableRule) SetIpvs(ipvs bool) *IpTableRule {
	r.ipvs = ipvs
	return r
}

func (r *IpTableRule) SetIpvsVaddr(ipvsVaddr string) *IpTableRule {
	r.ipvsVaddr = ipvsVaddr
	return r
}

func (r *IpTableRule) SetIpvsVport(ipvsVport string) *IpTableRule {
	r.ipvsVport = ipvsVport
	return r
}

func (r *IpTableRule) GetChainName() string {
	return r.chainName
}

func (r *IpTableRule) GetProto() string {
	return r.proto
}

func (r *IpTableRule) GetIcmpType() string {
	return formatIcmpCode(r.icmpType)
}

func (r *IpTableRule) GetSrcIp() string {
	return r.srcIp
}

func (r *IpTableRule) GetDstIp() string {
	return r.dstIp
}

func (r *IpTableRule) GetSrcIpRange() string {
	return r.srcIpRange
}

func (r *IpTableRule) GetDstIpRange() string {
	return r.dstIpRange
}

func (r *IpTableRule) GetSrcPort() string {
	return r.srcPort
}

func (r *IpTableRule) GetDstPort() string {
	return r.dstPort
}

func (r *IpTableRule) GetState() []string {
	return r.states
}

func (r *IpTableRule) GetComment() string {
	return r.comment
}

func (r *IpTableRule) GetInNic() string {
	return r.inNic
}

func (r *IpTableRule) GetOutNic() string {
	return r.outNic
}

func (r *IpTableRule) GetTcpFlags() []string {
	return r.tcpFlags
}

func (r *IpTableRule) GetMark() int {
	return r.mark
}

func (r *IpTableRule) GetMarkType() IptablesMarkType {
	return r.markType
}

func (r *IpTableRule) GetSrcIpset() string {
	return r.srcIpSet
}

func (r *IpTableRule) GetSrcIpPortset() string {
	return r.srcIpPortSet
}

func (r *IpTableRule) GetDstIpset() string {
	return r.dstIpSet
}

func (r *IpTableRule) GetDstIpPortset() string {
	return r.dstIpPortSet
}

func (r *IpTableRule) GetIpvs() bool {
	return r.ipvs
}

func (r *IpTableRule) GetIpvsVport() string {
	return r.ipvsVport
}

func (r *IpTableRule) GetIpvsVaddr() string {
	return r.ipvsVaddr
}

func (r *IpTableRule) isMatcherEqual(o *IpTableRule) error {
	if r.chainName != o.chainName {
		return fmt.Errorf("not match, old chainName: %s, new chainName: %s", r.chainName, o.chainName)
	}

	if r.proto != o.proto {
		return fmt.Errorf("not match, old protocol: %s, new protocol: %s", r.proto, o.proto)
	}

	if r.icmpType != o.icmpType {
		return fmt.Errorf("not match, old icmp type: %s, new icmp type: %s", r.icmpType, o.icmpType)
	}

	if r.srcIp != o.srcIp {
		return fmt.Errorf("not match, old srcIp Ip: %s, new srcIp Ip: %s", r.srcIp, o.srcIp)
	}

	if r.dstIp != o.dstIp {
		return fmt.Errorf("not match, old dst Ip: %s, new dst Ip: %s", r.dstIp, o.dstIp)
	}

	if r.srcIpRange != o.srcIpRange {
		return fmt.Errorf("not match, old src ip range: %s, new src ip range: %s", r.srcIpRange, o.srcIpRange)
	}

	if r.dstIpRange != o.dstIpRange {
		return fmt.Errorf("not match, old dst ip range: %s, new dst ip range: %s", r.dstIpRange, o.dstIpRange)
	}

	if r.srcPort != o.srcPort {
		return fmt.Errorf("not match, old srcIp port: %s, new srcIp port: %s", r.srcPort, o.srcPort)
	}

	if r.dstPort != o.dstPort {
		return fmt.Errorf("not match, old dst port: %s, new dst port: %s", r.dstPort, o.dstPort)
	}

	/* don't compare comment
	   if r.comment != o.comment {
	       return fmt.Errorf("not match, old comment: %s, new comment: %s", r.comment, o.comment)
	   } */

	if r.inNic != o.inNic {
		return fmt.Errorf("not match, old input nic: %s, new input nic: %s", r.inNic, o.inNic)
	}

	if r.outNic != o.outNic {
		return fmt.Errorf("not match, old output nic: %s, new output nic: %s", r.outNic, o.outNic)
	}

	if r.mark != o.mark {
		return fmt.Errorf("not match, old mark: %d, new mark: %d", r.mark, o.mark)
	}

	if r.markType != o.markType {
		return fmt.Errorf("not match, old mark match: %v, new mark match: %v", r.markType, o.markType)
	}

	if r.srcIpSet != o.srcIpSet {
		return fmt.Errorf("not match, old srcIp Ipset: %s, new srcIp Ipset: %s", r.srcIpSet, o.srcIpSet)
	}

	if r.srcIpPortSet != o.srcIpPortSet {
		return fmt.Errorf("not match, old srcIpPortSet Ipset: %s, new srcIpPortSet Ipset: %s", r.srcIpPortSet, o.srcIpPortSet)
	}

	if r.dstIpSet != o.dstIpSet {
		return fmt.Errorf("not match, old dst Ipset: %s, new dst Ipset: %s", r.dstIpSet, o.dstIpSet)
	}

	if r.dstIpPortSet != o.dstIpPortSet {
		return fmt.Errorf("not match, old dst dstIpPortSet: %s, new dst dstIpPortSet: %s", r.dstIpPortSet, o.dstIpPortSet)
	}

	if r.ipvs != o.ipvs {
		return fmt.Errorf("not match, old ipvs: %s, new ipvs: %s", r.ipvs, o.ipvs)
	}

	if r.ipvsVaddr != o.ipvsVaddr {
		return fmt.Errorf("not match, old ipvsVaddr: %s, new ipvsVaddr: %s", r.ipvsVaddr, o.ipvsVaddr)
	}

	if r.ipvsVport != o.ipvsVport {
		return fmt.Errorf("not match, old ipvsVport: %s, new ipvsVport: %s", r.ipvsVport, o.ipvsVport)
	}

	if len(r.states) != len(o.states) {
		return fmt.Errorf("not match, old state length: %d, new state length: %d", len(r.states), len(o.states))
	}
	if len(r.states) != 0 {
		stateNew := make([]string, len(r.states))
		copy(stateNew, r.states)
		stateOld := make([]string, len(o.states))
		copy(stateOld, o.states)
		sort.Strings(stateNew)
		sort.Strings(stateOld)
		for i, _ := range stateNew {
			if stateNew[i] != stateOld[i] {
				return fmt.Errorf("not match, old state: %s, new state: %s", stateNew, stateOld)
			}
		}
	}

	if len(r.tcpFlags) != len(o.tcpFlags) {
		return fmt.Errorf("not match, old tcp flag length: %d, new tcp flag length: %d", len(r.tcpFlags), len(o.tcpFlags))
	}
	if len(r.tcpFlags) != 0 {
		tcpFlagsNew := make([]string, len(r.tcpFlags))
		copy(tcpFlagsNew, r.tcpFlags)
		tcpFlagsOld := make([]string, len(o.tcpFlags))
		copy(tcpFlagsOld, o.tcpFlags)
		sort.Strings(tcpFlagsNew)
		sort.Strings(tcpFlagsOld)
		for i, _ := range tcpFlagsNew {
			if tcpFlagsNew[i] != tcpFlagsOld[i] {
				return fmt.Errorf("not match, old flags: %s, new flags: %s", tcpFlagsNew, tcpFlagsOld)
			}
		}
	}

	if r.priority != 0 && o.priority != 0 && r.priority != o.priority {
		return fmt.Errorf("not match, old priority: %d, new priority: %d", o.priority, r.priority)
	}

	if r.snatTargetIp != o.snatTargetIp {
		return fmt.Errorf("not match, old snatTargetIp: %s, new snatTargetIp: %s", o.snatTargetIp, r.snatTargetIp)
	}

	return nil
}

func (r *IpTableRule) matcherString() string {
	var rules []string
	if r.chainName != "" {
		rules = append(rules, "-A "+r.chainName)
	}

	protoAdded := false
	if r.srcIp != "" {
		items := strings.Fields(r.srcIp)
		if items[0] == "!" {
			rules = append(rules, "! -s "+items[1])
		} else {
			rules = append(rules, "-s "+items[0])
		}
	}

	if r.srcIpRange != "" {
		items := strings.Fields(r.srcIpRange)
		if items[0] == "!" {
			rules = append(rules, "-m iprange ! --src-range "+items[1])
		} else {
			rules = append(rules, "-m iprange --src-range "+items[0])
		}
	}

	if r.dstIp != "" {
		items := strings.Fields(r.dstIp)
		if items[0] == "!" {
			rules = append(rules, "! -d "+items[1])
		} else {
			rules = append(rules, "-d "+items[0])
		}
	}

	if r.dstIpRange != "" {
		items := strings.Fields(r.dstIpRange)
		if items[0] == "!" {
			rules = append(rules, "-m iprange ! --dst-range "+items[1])
		} else {
			rules = append(rules, "-m iprange --dst-range "+items[0])
		}
	}

	if r.inNic != "" {
		items := strings.Fields(r.inNic)
		if items[0] == "!" {
			rules = append(rules, "! -i "+items[1])
		} else {
			rules = append(rules, "-i "+items[0])
		}
	}

	if r.outNic != "" {
		items := strings.Fields(r.outNic)
		if items[0] == "!" {
			rules = append(rules, "! -o "+items[1])
		} else {
			rules = append(rules, "-o "+items[0])
		}
	}

	if r.proto != "" {
		items := strings.Fields(r.proto)
		Proto := r.proto
		if items[0] == "!" {
			if !protoAdded {
				rules = append(rules, "! -p "+items[1])
			}
			Proto = items[1]
		} else {
			if !protoAdded {
				rules = append(rules, "-p "+r.proto)
			}
		}

		if r.proto == IPTABLES_PROTO_TCP && r.tcpFlags != nil {
			rules = append(rules, fmt.Sprintf("-m tcp --tcp-flags %s %s", strings.Join(r.tcpFlags, ","), strings.Join(r.tcpFlags, ",")))
		}

		if r.proto == IPTABLES_PROTO_ICMP && r.icmpType != "" {
			rules = append(rules, fmt.Sprintf("-m icmp --icmp-type %s", r.icmpType))
		}

		if r.srcPort != "" {
			fields := strings.Fields(r.srcPort)
			if strings.ContainsAny(r.srcPort, ",:") {
				if fields[0] == "!" {
					rules = append(rules, "-m multiport")
					rules = append(rules, fmt.Sprintf("! --sports %s", strings.Join(fields[1:], " ")))
				} else {
					rules = append(rules, "-m multiport")
					rules = append(rules, fmt.Sprintf("--sports %s", r.srcPort))
				}
			} else {
				if fields[0] == "!" {
					rules = append(rules, "-m "+Proto)
					rules = append(rules, fmt.Sprintf("! --sport %s", strings.Join(fields[1:], " ")))
				} else {
					rules = append(rules, "-m "+Proto)
					rules = append(rules, fmt.Sprintf("--sport %s", r.srcPort))
				}
			}
		}

		if r.dstPort != "" {
			fields := strings.Fields(r.dstPort)
			if strings.ContainsAny(r.dstPort, ",:") {
				if fields[0] == "!" {
					rules = append(rules, "-m multiport")
					rules = append(rules, fmt.Sprintf("! --dports %s", strings.Join(fields[1:], " ")))
				} else {
					rules = append(rules, "-m multiport")
					rules = append(rules, fmt.Sprintf("--dports %s", r.dstPort))
				}
			} else {
				if fields[0] == "!" {
					rules = append(rules, "-m "+Proto)
					rules = append(rules, fmt.Sprintf("! --dport %s", strings.Join(fields[1:], " ")))
				} else {
					rules = append(rules, "-m "+Proto)
					rules = append(rules, fmt.Sprintf("--dport %s", r.dstPort))
				}
			}

		}
	}

	if r.comment != "" {
		rules = append(rules, "-m comment --comment \""+r.comment+"\"")
	}

	if r.states != nil {
		if r.states[0] == "!" {
			rules = append(rules, "-m state ! --state "+strings.Join(r.states[1:], ","))
		} else {
			rules = append(rules, "-m state --state "+strings.Join(r.states, ","))
		}
	}

	if r.srcIpSet != "" {
		items := strings.Fields(r.srcIpSet)
		if items[0] == "!" {
			rules = append(rules, "-m set ! --match-set "+items[1]+" src")
		} else {
			rules = append(rules, "-m set --match-set "+r.srcIpSet+" src")
		}
	}

	if r.srcIpPortSet != "" {
		items := strings.Fields(r.srcIpPortSet)
		if items[0] == "!" {
			rules = append(rules, "-m set ! --match-set "+items[1]+" src,src")
		} else {
			rules = append(rules, "-m set --match-set "+r.srcIpPortSet+" src,src")
		}
	}

	if r.dstIpSet != "" {
		items := strings.Fields(r.dstIpSet)
		if items[0] == "!" {
			rules = append(rules, "-m set ! --match-set "+items[1]+" dst")
		} else {
			rules = append(rules, "-m set --match-set "+r.dstIpSet+" dst")
		}
	}

	if r.dstIpPortSet != "" {
		items := strings.Fields(r.dstIpPortSet)
		if items[0] == "!" {
			rules = append(rules, "-m set ! --match-set "+items[1]+" dst,dst")
		} else {
			rules = append(rules, "-m set --match-set "+r.dstIpPortSet+" dst,dst")
		}
	}

	if r.ipvs {
		rules = append(rules, "-m ipvs --ipvs")
		if r.ipvsVaddr != "" {
			rules = append(rules, "--vaddr "+r.ipvsVaddr)
		}
		if r.ipvsVport != "" {
			rules = append(rules, "--vport  "+r.ipvsVport)
		}
	}

	if r.markType == IptablesMarkNotMatch {
		rules = append(rules, fmt.Sprintf("-m mark ! --mark %d", r.mark))
	} else if r.markType == IptablesMarkMatch {
		rules = append(rules, fmt.Sprintf("-m mark --mark %d", r.mark))
	}

	return strings.Join(rules, " ")
}

func (r *IpTableRule) parseIpTablesMatcher(line string, chains []*IpTableChain) (*IpTableRule, error) {
	items := strings.Fields(line)

	if items[0] != "-A" {
		log.Debugf("parseIpTablesRule %s failed", line)
		return nil, fmt.Errorf("iptable matcher parse error %s", line)
	}

	r.chainName = items[1]
	found := false
	for _, c := range chains {
		if c.Name == r.chainName {
			found = true
			break
		}
	}
	if !found {
		log.Debugf("parseIpTablesMatcher items [%s] not found, current chains [%s]", items[1], chains)
		return nil, fmt.Errorf("iptable matcher parse error: itmes [%s] not existed %s", items, chains)
	}

	notMatch := false

	for i := 2; i < len(items); i++ {
		switch items[i] {
		case "!":
			notMatch = true
			break

		case "-d": //-d 172.20.11.156/32;
			i++
			if notMatch {
				r.dstIp = "! " + items[i]
			} else {
				r.dstIp = items[i]
			}
			notMatch = false

			break

		case "-s": // -s 10.86.0.221/32;
			i++
			if notMatch {
				r.srcIp = "! " + items[i]
			} else {
				r.srcIp = items[i]
			}
			notMatch = false

			break
		case "--src-range": // --src-range 172.16.90.1-172.16.90.10
			i++
			if notMatch {
				r.srcIpRange = "! " + items[i]
			} else {
				r.srcIpRange = items[i]
			}
			notMatch = false

			break
		case "--dst-range": //--dst-range 172.16.90.1-172.16.90.10
			i++
			if notMatch {
				r.dstIpRange = "! " + items[i]
			} else {
				r.dstIpRange = items[i]
			}
			notMatch = false

			break

		case "-p": // -p tcp
			i++
			if notMatch {
				r.proto = "! " + items[i]
			} else {
				r.proto = items[i]
			}
			notMatch = false

			break

		case "--dport": // --dports 1000:2000
			i++
			if notMatch {
				r.dstPort = "! " + items[i]
			} else {
				r.dstPort = items[i]
			}
			notMatch = false
			break

		case "--dports": // --dports 1000,1002,1004,100:200
			i++
			if notMatch {
				r.dstPort = "! " + items[i]
			} else {
				r.dstPort = items[i]
			}
			notMatch = false

			break

		case "--sport": // --sport 500
			i++
			if notMatch {
				r.srcPort = "! " + items[i]
			} else {
				r.srcPort = items[i]
			}

			notMatch = false
			break

		case "--sports": // --sports 1000,1002,1004,100:200
			i++
			if notMatch {
				r.srcPort = "! " + items[i]
			} else {
				r.srcPort = items[i]
			}

			notMatch = false
			break

		case "-o": // -o eth5
			i++
			if notMatch {
				r.outNic = "! " + items[i]
			} else {
				r.outNic = items[i]
			}
			notMatch = false

			break

		case "-i": // -i eth1
			i++
			if notMatch {
				r.inNic = "! " + items[i]
			} else {
				r.inNic = items[i]
			}
			notMatch = false

			break

		case "-m": //-m comment, -m tcp, -m state, -m mark, -m icmp
			i++
			break

		case "--comment": // --comment dstIp-NAT-1
			i++
			found := false
			j := i
			for ; j < len(items); j++ {
				l := len(items[j])
				if items[j][l-1] == '"' {
					found = true
					break
				}
			}
			if !found {
				r.comment = items[i]
			} else {
				r.comment = strings.Trim(strings.Join(items[i:j+1], " "), "\"")
			}

			break

		case "--state": // --state NEW,RELATED,ESTABLISHED
			i++
			if notMatch {
				r.states = []string{"!"} // first element indicate match or not
				for _, s := range strings.Split(items[i], ",") {
					r.states = append(r.states, s)
				}
			} else {
				r.states = strings.Split(items[i], ",")
			}
			notMatch = false
			break

		case "--match-set": //--match-set ipsec-group srcIp
			i++
			ipset := items[i]
			i++
			if items[i] == "src" {
				if notMatch {
					r.srcIpSet = "! " + ipset
				} else {
					r.srcIpSet = ipset
				}
			} else if items[i] == "src,src" {
				if notMatch {
					r.srcIpPortSet = "! " + ipset
				} else {
					r.srcIpPortSet = ipset
				}
			} else if items[i] == "dst" {
				if notMatch {
					r.dstIpSet = "! " + ipset
				} else {
					r.dstIpSet = ipset
				}
			} else if items[i] == "dst,dst" {
				if notMatch {
					r.dstIpPortSet = "! " + ipset
				} else {
					r.dstIpPortSet = ipset
				}
			}
			notMatch = false
			break

		case "--ipvs": /* --ipvs */
			r.ipvs = true
			break

		case "--vaddr": /* --vaddr 192.168.100.30/32 */
			i++
			r.ipvsVaddr = items[i]
			i++
			break

		case "--vport": /* --vaddr 192.168.100.30/32 */
			i++
			r.ipvsVport = items[i]
			i++
			break

		case "--tcp-flags": /* --tcp-flags SYN,RST SYN,RST */
			i++
			r.tcpFlags = strings.Split(items[i], ",")
			i++
			break

		case "--mark": /* --mark 0x0 */
			i++
			v, _ := strconv.ParseUint(items[i], 0, 64)
			if notMatch {
				r.markType = IptablesMarkNotMatch
			} else {
				r.markType = IptablesMarkMatch
			}
			r.mark = int(v)
			i++
			break

		case "--icmp-type": /* --icmp-type 0 */
			i++
			r.icmpType = items[i]
			i++
			break

		default:

		}
	}

	return r, nil
}
