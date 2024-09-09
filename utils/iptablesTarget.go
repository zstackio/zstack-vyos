package utils

import (
	"fmt"
	//log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
)

const (
	IPTABLES_ACTION_ACCEPT           = "ACCEPT"
	IPTABLES_ACTION_RETURN           = "RETURN"
	IPTABLES_ACTION_REJECT           = "REJECT"
	IPTABLES_ACTION_DNAT             = "DNAT"
	IPTABLES_ACTION_SNAT             = "SNAT"
	IPTABLES_ACTION_DROP             = "DROP"
	IPTABLES_ACTION_MARK             = "MARK"
	IPTABLES_ACTION_CONNMARK         = "CONNMARK"
	IPTABLES_ACTION_CONNMARK_RESTORE = "CONNMARK_RESTORE"
	IPTABLES_ACTION_LOG              = "LOG"

	REJECT_TYPE_ICMP_UNREACHABLE = "icmp-port-unreachable"
)

type IpTableTarget struct {
	action         string
	dnatTargetIp   string
	dnatTargetPort string
	snatTargetIp   string
	rejectType     string
	targetMark     int
	logPrefix      string
}

func (r *IpTableRule) SetAction(Action string) *IpTableRule {
	r.action = Action
	return r
}

func (r *IpTableRule) SetActionLog(logprefix string) *IpTableRule {
	r.action = IPTABLES_ACTION_LOG
	r.logPrefix = logprefix
	return r
}

func (r *IpTableRule) SetDnatTargetIp(targetIp string) *IpTableRule {
	r.dnatTargetIp = targetIp
	return r
}

func (r *IpTableRule) SetDnatTargetPort(targetPort string) *IpTableRule {
	r.dnatTargetPort = targetPort
	return r
}

func (r *IpTableRule) SetSnatTargetIp(targetIp string) *IpTableRule {
	r.snatTargetIp = targetIp
	return r
}

func (r *IpTableRule) SetRejectType(RejectType string) *IpTableRule {
	r.rejectType = RejectType
	return r
}

func (r *IpTableRule) SetTargetMark(TargetMark int) *IpTableRule {
	r.targetMark = TargetMark
	return r
}

func (r *IpTableRule) GetAction() string {
	return r.action
}

func (r *IpTableRule) GetDnatTargetIp() string {
	return r.dnatTargetIp
}

func (r *IpTableRule) GetDnatTargetPort() string {
	return r.dnatTargetPort
}

func (r *IpTableRule) GetSnatTargetIp() string {
	return r.snatTargetIp
}

func (r *IpTableRule) GetRejectType() string {
	return r.rejectType
}

func (r *IpTableRule) GetTargetMark() int {
	return r.targetMark
}

func (r *IpTableRule) IsTargetEqual(o *IpTableRule) error {
	if r.action != o.action {
		return fmt.Errorf("iptables target is different, action %s:%s", r.action, o.action)
	}

	if r.dnatTargetIp != o.dnatTargetIp {
		return fmt.Errorf("iptables target is different, dnatTargetIp %s:%s", r.dnatTargetIp, o.dnatTargetIp)
	}

	if r.dnatTargetPort != o.dnatTargetPort {
		return fmt.Errorf("iptables target is different, action %s:%s", r.dnatTargetPort, o.dnatTargetPort)
	}

	if r.snatTargetIp != o.snatTargetIp {
		return fmt.Errorf("iptables target is different, action %s:%s", r.snatTargetIp, o.snatTargetIp)
	}

	if r.rejectType != o.rejectType {
		return fmt.Errorf("iptables target is different, action %s:%s", r.rejectType, o.rejectType)
	}

	if r.targetMark != o.targetMark {
		return fmt.Errorf("iptables target is different, action %d:%d", r.targetMark, o.targetMark)
	}

	if r.logPrefix != o.logPrefix {
		return fmt.Errorf("iptables target is different, action %s:%s", r.logPrefix, o.logPrefix)
	}

	return nil
}

func (r *IpTableRule) targetString() string {
	var rules []string

	switch r.action {
	case IPTABLES_ACTION_REJECT:
		if r.rejectType != "" {
			rules = append(rules, "-j REJECT --reject-with "+r.rejectType)
		} else {
			rules = append(rules, "-j REJECT --reject-with icmp-port-unreachable")
		}

	case IPTABLES_ACTION_DNAT:
		if r.dnatTargetPort != "" {
			rules = append(rules, fmt.Sprintf("-j DNAT --to-destination %s:%s", r.dnatTargetIp, r.dnatTargetPort))
		} else {
			rules = append(rules, fmt.Sprintf("-j DNAT --to-destination %s", r.dnatTargetIp))
		}
	case IPTABLES_ACTION_SNAT:
		rules = append(rules, fmt.Sprintf("-j SNAT --to-source %s", r.snatTargetIp))
	case IPTABLES_ACTION_MARK:
		rules = append(rules, fmt.Sprintf("-j MARK  --set-mark %d", r.targetMark))
	case IPTABLES_ACTION_CONNMARK:
		rules = append(rules, fmt.Sprintf("-j CONNMARK --set-mark %d", r.targetMark))
	case IPTABLES_ACTION_CONNMARK_RESTORE:
		rules = append(rules, fmt.Sprintf("-j CONNMARK --restore-mark"))
	case IPTABLES_ACTION_LOG:
		rules = append(rules, fmt.Sprintf("-j LOG --log-prefix %s", r.logPrefix))
	default:
		rules = append(rules, "-j "+r.action)
	}

	return strings.Join(rules, " ")
}

func (r *IpTableRule) parseIptablesTarget(line string) (*IpTableRule, error) {
	items := strings.Fields(line)
	for i := 0; i < len(items); i++ {
		switch items[i] {
		case "-j": //-j DNAT, -j CONNMARK, -j MARK
			i++
			r.action = items[i]
			if r.action == IPTABLES_ACTION_LOG { //-j LOG --log-prefix "[eth2.out-default-A]"
				i = i + 2
				r.logPrefix = items[i]
			}
			break

		case "--to-destination": // --to-destination 10.86.4.109:1000-2000
			i++
			fields := strings.Split(items[i], ":")
			if len(fields) > 1 {
				r.dnatTargetIp = fields[0]
				r.dnatTargetPort = fields[1]
			} else {
				r.dnatTargetIp = fields[0]
			}

			break

		case "--to-source":
			i++
			r.snatTargetIp = items[i]
			break

		case "--reject-with":
			i++
			r.rejectType = items[i]
			break

		case "--set-xmark": /* --set-xmark 0xb5/0xffffffff */
			i++
			fields := strings.Split(items[i], "/")
			v, _ := strconv.ParseInt(fields[0], 0, 64)
			r.targetMark = int(v)
			break

		case "--restore-mark": /*--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff*/
			i++
			r.action = IPTABLES_ACTION_CONNMARK_RESTORE
			break

		default:

		}
	}

	return r, nil
}
