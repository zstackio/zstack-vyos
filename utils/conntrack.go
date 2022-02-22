package utils

import "fmt"

type ConnectionTrackTuple struct {
	Ip        string
	Protocol  string
	PortStart int
	PortEnd   int
	IsNat     bool
	IsDst     bool
	State     string
}

func (t ConnectionTrackTuple) CleanConnTrackConnection() error {
	var command string
	if t.IsDst && !t.IsNat {
		if t.Protocol == "" {
			command = fmt.Sprintf("sudo conntrack -d %s -D", t.Ip)
		} else if t.PortStart == 0 {
			command = fmt.Sprintf("sudo conntrack -d %s -p %s -D", t.Ip, t.Protocol)
		} else if t.PortStart == t.PortEnd {
			command = fmt.Sprintf("sudo conntrack -d %s -p %s --dport %d -D", t.Ip, t.Protocol, t.PortStart)
		} else {
			command = fmt.Sprintf("sudo conntrack -d %s -p %s --dport %d-%d -D", t.Ip, t.Protocol, t.PortStart, t.PortEnd)
		}
	} else if !t.IsDst && !t.IsNat {
		if t.Protocol == "" {
			command = fmt.Sprintf("sudo conntrack -s %s -D", t.Ip)
		} else if t.PortStart == 0 {
			command = fmt.Sprintf("sudo conntrack -s %s -p %s -D", t.Ip, t.Protocol)
		} else if t.PortStart == t.PortEnd {
			command = fmt.Sprintf("sudo conntrack -s %s -p %s --sport %d -D", t.Ip, t.Protocol, t.PortStart)
		} else {
			command = fmt.Sprintf("sudo conntrack -s %s -p %s --sport %d-%d -D", t.Ip, t.Protocol, t.PortStart, t.PortEnd)
		}
	} else if t.IsDst && t.IsNat {
		if t.Protocol == "" {
			command = fmt.Sprintf("sudo conntrack -g %s -D", t.Ip)
		} else if t.PortStart == 0 {
			command = fmt.Sprintf("sudo conntrack -g %s -p %s -D", t.Ip, t.Protocol)
		} else if t.PortStart == t.PortEnd {
			command = fmt.Sprintf("sudo conntrack -g %s -p %s --dport %d -D", t.Ip, t.Protocol, t.PortStart)
		} else {
			command = fmt.Sprintf("sudo conntrack -g %s -p %s --dport %d-%d -D", t.Ip, t.Protocol, t.PortStart, t.PortEnd)
		}
	} else {
		if t.Protocol == "" {
			command = fmt.Sprintf("sudo conntrack -n %s -D", t.Ip)
		} else if t.PortStart == 0 {
			command = fmt.Sprintf("sudo conntrack -n %s -p %s -D", t.Ip, t.Protocol)
		} else if t.PortStart == t.PortEnd {
			command = fmt.Sprintf("sudo conntrack -n %s -p %s --sport %d -D", t.Ip, t.Protocol, t.PortStart)
		} else {
			command = fmt.Sprintf("sudo conntrack -n %s -p %s --sport %d-%d -D", t.Ip, t.Protocol, t.PortStart, t.PortEnd)
		}
	}

	if t.State != "" {
		if t.Protocol != "" {
			command = command + " --state " + t.State
		}
	}

	bash := Bash{
		Command: command,
	}
	bash.Run()

	return nil
}
