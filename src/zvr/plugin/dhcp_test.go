package plugin

import (
	"testing"
	"zvr/server"
	"fmt"
)

var infos = []dhcpInfo {
	dhcpInfo{
		VrNicMac: "fa:62:6b:d9:10:00",
		Ip: "172.20.14.16",
		Netmask: "255.255.0.0",
		Gateway: "172.20.14.114",
		Dns: []string{"8.8.8.8", "114.114.114.114"},
		DnsDomain: "zstack.org",
		IsDefaultL3Network: true,
		Hostname: "172-120-14-16",
		Mac: "fa:da:21:1f:1a:11",
	},

	dhcpInfo{
		VrNicMac: "fa:62:6b:d9:10:00",
		Ip: "172.20.14.17",
		Netmask: "255.255.0.0",
		Gateway: "172.20.14.114",
		Dns: []string{"8.8.8.8", "114.114.114.114"},
		DnsDomain: "zstack.org",
		IsDefaultL3Network: true,
		Hostname: "172-120-14-17",
		Mac: "fa:da:21:1f:1b:11",
	},

	// not existing one, for TestDHCPRemoveEntry
	dhcpInfo{
		VrNicMac: "fa:62:6b:d9:10:00",
		Ip: "172.20.14.18",
		Netmask: "255.255.0.0",
		Gateway: "172.20.14.114",
		Dns: []string{"8.8.8.8", "114.114.114.114"},
		DnsDomain: "zstack.org",
		IsDefaultL3Network: true,
		Hostname: "172-120-14-17",
		Mac: "fa:63:21:1f:1b:11",
	},
}

func TestDHCPRebuildEntry(t *testing.T) {
	server.UNIT_TEST = true
	runVyosScript = func(script string, args map[string]string) {
		fmt.Println(script)
	}

	server.ConfigurationSourceFunc = func() string {
		return `
interfaces {
    ethernet eth0 {
        address 172.20.14.114/16
        description main
        duplex auto
        hw-id fa:62:6b:d9:10:00
        smp_affinity auto
        speed auto
    }
    loopback lo {
    }
}

service {
    dhcp-server {
        shared-network-name eth0_subnet {
            authoritative enable
            subnet 172.20.0.0/16 {
                static-mapping fa_62_6b_d9_10_00 {
                    ip-address 172.20.14.114
                    mac-address fa:62:6b:d9:10:00
                }
                static-mapping fa_da_21_1f_1a_11 {
                    ip-address 172.20.14.16
                    mac-address fa:da:21:1f:1a:11
                    static-mapping-parameters "option option subnet-mask 255.255.0.0;"
                    static-mapping-parameters "option host-name &quot;172-120-14-16&quot;;"
                    static-mapping-parameters "option domain-name-servers 8.8.8.8,114.114.114.114;"
                    static-mapping-parameters "option routers 172.20.14.114;"
                    static-mapping-parameters "option domain-name &quot;zstack.org&quot;;"
                }
                static-mapping fa_da_21_1f_1b_11 {
                    ip-address 172.20.14.17
                    mac-address fa:da:21:1f:1b:11
                    static-mapping-parameters "option option subnet-mask 255.255.0.0;"
                    static-mapping-parameters "option host-name &quot;172-120-14-17&quot;;"
                    static-mapping-parameters "option domain-name-servers 8.8.8.8,114.114.114.114;"
                    static-mapping-parameters "option routers 172.20.14.114;"
                    static-mapping-parameters "option domain-name &quot;zstack.org&quot;;"
                }
            }
        }
    }
    ssh {
        port 22
    }
}`
	}

	deleteDhcp(infos)
	setDhcp(infos)
}

func TestDHCPRemoveEntry(t *testing.T) {
	server.UNIT_TEST = true
	runVyosScript = func(script string, args map[string]string) {
		fmt.Println(script)
	}

	server.ConfigurationSourceFunc = func() string {
		return `
interfaces {
    ethernet eth0 {
        address 172.20.14.114/16
        description main
        duplex auto
        hw-id fa:62:6b:d9:10:00
        smp_affinity auto
        speed auto
    }
    loopback lo {
    }
}

service {
    dhcp-server {
        shared-network-name eth0_subnet {
            authoritative enable
            subnet 172.20.0.0/16 {
                static-mapping fa_62_6b_d9_10_00 {
                    ip-address 172.20.14.114
                    mac-address fa:62:6b:d9:10:00
                }
                static-mapping fa_da_21_1f_1a_11 {
                    ip-address 172.20.14.16
                    mac-address fa:da:21:1f:1a:11
                    static-mapping-parameters "option option subnet-mask 255.255.0.0;"
                    static-mapping-parameters "option host-name &quot;172-120-14-16&quot;;"
                    static-mapping-parameters "option domain-name-servers 8.8.8.8,114.114.114.114;"
                    static-mapping-parameters "option routers 172.20.14.114;"
                    static-mapping-parameters "option domain-name &quot;zstack.org&quot;;"
                }
                static-mapping fa_da_21_1f_1b_11 {
                    ip-address 172.20.14.17
                    mac-address fa:da:21:1f:1b:11
                    static-mapping-parameters "option option subnet-mask 255.255.0.0;"
                    static-mapping-parameters "option host-name &quot;172-120-14-17&quot;;"
                    static-mapping-parameters "option domain-name-servers 8.8.8.8,114.114.114.114;"
                    static-mapping-parameters "option routers 172.20.14.114;"
                    static-mapping-parameters "option domain-name &quot;zstack.org&quot;;"
                }
            }
        }
    }
    ssh {
        port 22
    }
}`
	}

	deleteDhcp(infos)
}

func TestDHCPAddEntry(t *testing.T) {
	server.UNIT_TEST = true
	runVyosScript = func(script string, args map[string]string) {
		fmt.Println(script)
	}

	server.ConfigurationSourceFunc = func() string {
		return `
interfaces {
    ethernet eth0 {
        address 172.20.14.114/16
        description main
        duplex auto
        hw-id fa:62:6b:d9:10:00
        smp_affinity auto
        speed auto
    }
    loopback lo {
    }
}`
	}

	setDhcp(infos)
}
