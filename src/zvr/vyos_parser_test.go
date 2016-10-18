package zvr

import (
	"testing"
	"fmt"
	"zvr/utils"
)

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
    ethernet eth1 {
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
	p.Parse(text)
	addr, ok := p.GetValue("interfaces", "ethernet", "eth0", "address")
	utils.Assert(ok, "fail")
	fmt.Println(addr)

	c, ok := p.GetConfig("interfaces", "ethernet", "eth0")
	utils.Assert(ok, "fail")

	addr, ok = c.GetValue("address")
	utils.Assert(ok, "fail")
	fmt.Println(addr)

	c, ok = p.GetConfig("interfaces", "ethernet", "eth0", "Asdfasdf")
	utils.Assert(!ok, "fail")

	value, ok := p.GetValue("system", "time-zone")
	utils.Assert(ok, "fail")
	fmt.Println(value)

	value, ok = p.GetValue("ABC")
	utils.Assert(ok, "fail")
	fmt.Println(value)
}

