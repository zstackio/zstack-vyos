package server

import (
	"testing"
	"fmt"
	"zvr/utils"
)

func TestSetFirewall(t *testing.T) {
	UNIT_TEST = true

	ConfigurationSourceFunc = func() string {
		return ""
	}

	tree := NewParserFromShowConfiguration().Tree

	tree.SetFirewallOnInterface("eth0", "local",
		fmt.Sprintf("destination port %v", 7758),
		"protocol tcp",
		"action accept",
	)
	tree.SetFirewallOnInterface("eth0", "local",
		fmt.Sprintf("destination port %v", 7758),
		"protocol udp",
		"action accept",
	)
	tree.SetFirewallOnInterface("eth0", "local",
		fmt.Sprintf("destination port %v", 7759),
		"protocol udp",
		"action accept",
	)
	tree.AttachFirewallToInterface("eth0", "local")

	tree.Apply(false)
}

func TestVyosParser1(t *testing.T) {
	text := `
interfaces {
    ethernet eth0 {
        address 172.20.14.209/16
        description main
        duplex auto
        hw-id fa:da:21:1f:1a:00
        smp_affinity auto
        speed auto
    }
    loopback lo {
    }
}
nat {
    source {
        rule 100 {
            outbound-interface eth0
            source {
                address 192.168.0.0/24
            }
            translation {
                address masquerade
            }
        }
    }
}
protocols {
    static {
        route 0.0.0.0/0 {
            next-hop 172.20.0.1 {
                distance 1
            }
        }
    }
}
service {
    ssh {
        port 22
    }
}
system {
    config-management {
        commit-revisions 20
    }
    console {
        device ttyS0 {
            speed 9600
        }
        test
    }
    host-name vyos
    login {
        user vyos {
            authentication {
                encrypted-password ****************
                plaintext-password ****************
            }
            level admin
        }
    }
    ntp {
        server 0.pool.ntp.org {
        }
        server 1.pool.ntp.org {
        }
        server 2.pool.ntp.org {
        }
    }
    package {
        auto-sync 1
        repository community {
            components main
            distribution helium
            password ****************
            url http://packages.vyos.net/vyos
            username ""
        }
    }
    syslog {
        global {
            facility all {
                level notice
            }
            facility protocols {
                level debug
            }
        }
    }
    time-zone UTC
}

ABC E
`
	p := VyosParser{}
	tree := p.Parse(text)
	addr := tree.Get("interfaces ethernet eth0 address")
	utils.Assert("172.20.14.209/16" == addr.Value(), "not equal")
	fmt.Println(addr.Value())

	addr = tree.Get("interfaces ethernet eth0")
	utils.Assert(addr != nil, "fail")

	value := tree.Get("ABC"); utils.Assert(value.Value() == "E", "E")

	tree.Set("interfaces ethernet eth1 address 172.20.14.209/16")
	tree.Set("interfaces ethernet eth1 address 172.20.14.209/16")
	tree.Set("interfaces ethernet eth1 address 172.20.14.210/16")
	tree.Set("interfaces ethernet eth1 exclude")
	tree.Set("interfaces ethernet eth1 include")
	tree.Delete("interfaces ethernet eth0 address")
	tree.Delete("interfaces ethernet eth0 address")
	tree.Delete("system login user vyos authentication plaintext-password")
	tree.Set("system login user vyos authentication plaintext-password xxx")
	tree.Set("protocols static route 0.0.0.0/0 next-hop 172.20.0.1 distance 2")
	n := tree.Get("system package")
	n.Delete()
	fmt.Println(tree.CommandsAsString())
	fmt.Println(tree.String())
}

