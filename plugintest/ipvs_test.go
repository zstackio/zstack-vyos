package plugintest

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"time"
	"zstack-vyos/plugin"
	"zstack-vyos/utils"
)

import (
	"context"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ipvs test", func() {
	Context("slbha ipvs test", func() {
		env := NewSlbHaIp4Env()
		It("ipvs: test prepare env", func() {
			env.SetupStrap()
			env.SetupLb()
		})

		It("ipvs: test InitIpvs", func() {
			table := utils.NewIpTables(utils.NatTable)
			Expect(table.CheckChain(plugin.IPVS_LOG_CHAIN_NAME)).To(BeTrue(), "ipvs log chain created")
			Expect(table.CheckChain(plugin.IPVS_FULL_NAT_CHAIN_NAME)).To(BeTrue(), "ipvs log chain created")
		})

		It("ipvs: RefreshIpvsService", func() {
			env.AddPeerAddr("ut-pri", "192.168.3.10/24")
			env.AddPeerAddr("ut-pri", "192.168.3.11/24")

			ctx1, cancel1 := context.WithCancel(context.Background())
			ctx2, cancel2 := context.WithCancel(context.Background())
			go utils.StartUdpServer("192.168.3.10", 8080, ctx1)
			go utils.StartUdpServer("192.168.3.11", 8080, ctx2)

			plugin.RefreshIpvsService(map[string]plugin.LbInfo{env.lb.ListenerUuid: env.lb}, true)

			// check ipvs config
			wait := 5 //
			time.Sleep(time.Duration(wait) * time.Second)
			ipvs, _ := plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 1).To(BeTrue(), "ipvs frond service added")
			for _, fs := range ipvs.Services {
				Expect(len(fs.BackendServers) == 2).To(BeTrue(), "2 ipvs backend server added")
				for _, bs := range fs.BackendServers {
					Expect(bs.FrontIp == "192.168.2.100").To(BeTrue(), "ipvs backend server added")
					Expect(bs.FrontPort == "80").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ProtocolType == "-u").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ConnectionType == "-m").To(BeTrue(), "ipvs backend server added")
					Expect(bs.Scheduler == "rr").To(BeTrue(), "ipvs backend server added")
					Expect(bs.BackendIp == "192.168.3.10" || bs.BackendIp == "192.168.3.11").To(BeTrue(), "ipvs backend server is up")
					Expect(bs.BackendPort == "8080").To(BeTrue(), "ipvs backend server added")
				}
			}

			// check ipvs metrics
			plugin.UpdateIpvsCounters()
			fs := plugin.GetIpvsFrontService(env.lb.ListenerUuid)
			for _, bs := range fs.BackendServers {
				cnt := bs.Counter
				Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server is up")
			}
			cancel2()
			time.Sleep(time.Duration(wait) * time.Second)
			plugin.UpdateIpvsCounters()
			for _, bs := range fs.BackendServers {
				cnt := bs.Counter
				if bs.BackendIp == "192.168.3.10" {
					Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server(192.168.3.10) is up")
				} else {
					Expect(cnt.Status == 0).To(BeTrue(), "ipvs backend server(192.168.3.11) is down")
				}
			}
			cancel1()
			//wait udp server down
			time.Sleep(time.Duration(2) * time.Second)
		})

		It("ipvs: RefreshIpvsService to add 1 backend server", func() {
			env.AddPeerAddr("ut-pri", "192.168.3.12/24")

			env.lb.ServerGroups = append(env.lb.ServerGroups, env.sg1)
			ctx1, cancel1 := context.WithCancel(context.Background())
			ctx2, cancel2 := context.WithCancel(context.Background())
			ctx3, cancel3 := context.WithCancel(context.Background())
			go utils.StartUdpServer("192.168.3.10", 8080, ctx1)
			go utils.StartUdpServer("192.168.3.11", 8080, ctx2)
			go utils.StartUdpServer("192.168.3.12", 8080, ctx3)

			env.lb.ServerGroups[0].BackendServers = []plugin.BackendServerInfo{env.bs1, env.bs2, env.bs3}
			plugin.RefreshIpvsService(map[string]plugin.LbInfo{env.lb.ListenerUuid: env.lb}, true)

			// check ipvs config
			wait := 6 //
			time.Sleep(time.Duration(wait) * time.Second)
			ipvs, _ := plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 1).To(BeTrue(), "ipvs frond service added")
			for _, fs := range ipvs.Services {
				Expect(len(fs.BackendServers) == 3).To(BeTrue(), "3 ipvs backend server added")
				for _, bs := range fs.BackendServers {
					Expect(bs.FrontIp == "192.168.2.100").To(BeTrue(), "ipvs backend server added")
					Expect(bs.FrontPort == "80").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ProtocolType == "-u").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ConnectionType == "-m").To(BeTrue(), "ipvs backend server added")
					Expect(bs.Scheduler == "rr").To(BeTrue(), "ipvs backend server added")
					Expect(bs.BackendIp == "192.168.3.10" || bs.BackendIp == "192.168.3.11" || bs.BackendIp == "192.168.3.12").To(BeTrue(), "ipvs backend server is up")
					Expect(bs.BackendPort == "8080").To(BeTrue(), "ipvs backend server added")
				}
			}

			// check ipvs metrics
			plugin.UpdateIpvsCounters()
			fs := plugin.GetIpvsFrontService(env.lb.ListenerUuid)
			for _, bs := range fs.BackendServers {
				cnt := bs.Counter
				Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server is up")
			}

			// refresh ipvs without any change
			plugin.RefreshIpvsService(map[string]plugin.LbInfo{env.lb.ListenerUuid: env.lb}, true)

			// check ipvs config
			time.Sleep(time.Duration(wait) * time.Second)
			ipvs, _ = plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 1).To(BeTrue(), "ipvs frond service added")
			for _, fs := range ipvs.Services {
				Expect(len(fs.BackendServers) == 3).To(BeTrue(), "3 ipvs backend server added")
				for _, bs := range fs.BackendServers {
					Expect(bs.FrontIp == "192.168.2.100").To(BeTrue(), "ipvs backend server added")
					Expect(bs.FrontPort == "80").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ProtocolType == "-u").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ConnectionType == "-m").To(BeTrue(), "ipvs backend server added")
					Expect(bs.Scheduler == "rr").To(BeTrue(), "ipvs backend server added")
					Expect(bs.BackendIp == "192.168.3.10" || bs.BackendIp == "192.168.3.11" || bs.BackendIp == "192.168.3.12").To(BeTrue(), "ipvs backend server is up")
					Expect(bs.BackendPort == "8080").To(BeTrue(), "ipvs backend server added")
				}
			}

			// check ipvs metrics
			plugin.UpdateIpvsCounters()
			fs = plugin.GetIpvsFrontService(env.lb.ListenerUuid)
			for _, bs := range fs.BackendServers {
				cnt := bs.Counter
				Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server is up")
			}

			cancel1()
			cancel2()
			cancel3()
			//wait udp server down
			time.Sleep(time.Duration(2) * time.Second)
		})

		It("ipvs: RefreshIpvsService to del 1 backend server", func() {
			ctx1, cancel1 := context.WithCancel(context.Background())
			ctx2, cancel2 := context.WithCancel(context.Background())
			go utils.StartUdpServer("192.168.3.10", 8080, ctx1)
			go utils.StartUdpServer("192.168.3.11", 8080, ctx2)

			env.sg1.BackendServers = []plugin.BackendServerInfo{env.bs1, env.bs2}
			env.lb.ServerGroups = []plugin.ServerGroupInfo{env.sg1}
			plugin.RefreshIpvsService(map[string]plugin.LbInfo{env.lb.ListenerUuid: env.lb}, true)

			// check ipvs config
			wait := 6 //
			time.Sleep(time.Duration(wait) * time.Second)
			ipvs, _ := plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 1).To(BeTrue(), "ipvs frond service added")
			for _, fs := range ipvs.Services {
				Expect(len(fs.BackendServers) == 2).To(BeTrue(), "2 ipvs backend server added")
				for _, bs := range fs.BackendServers {
					Expect(bs.FrontIp == "192.168.2.100").To(BeTrue(), "ipvs backend server added")
					Expect(bs.FrontPort == "80").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ProtocolType == "-u").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ConnectionType == "-m").To(BeTrue(), "ipvs backend server added")
					Expect(bs.Scheduler == "rr").To(BeTrue(), "ipvs backend server added")
					Expect(bs.BackendIp == "192.168.3.10" || bs.BackendIp == "192.168.3.11").To(BeTrue(), "ipvs backend server is up")
					Expect(bs.BackendPort == "8080").To(BeTrue(), "ipvs backend server added")
				}
			}

			// check ipvs metrics
			plugin.UpdateIpvsCounters()
			fs := plugin.GetIpvsFrontService(env.lb.ListenerUuid)
			for _, bs := range fs.BackendServers {
				log.Debugf("bs key: %s, counter:%+v", bs.GetBackendKey(), bs.Counter)
				cnt := bs.Counter
				Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server is up")
			}

			cancel1()
			cancel2()
			//wait udp server down
			time.Sleep(time.Duration(2) * time.Second)
		})

		It("ipvs: RefreshIpvsService to add 1 front service", func() {
			ctx1, cancel1 := context.WithCancel(context.Background())
			ctx2, cancel2 := context.WithCancel(context.Background())
			ctx3, cancel3 := context.WithCancel(context.Background())
			go utils.StartUdpServer(env.bs1.Ip, env.lb.InstancePort, ctx1)
			go utils.StartUdpServer(env.bs2.Ip, env.lb.InstancePort, ctx2)
			go utils.StartUdpServer(env.bs3.Ip, env.lb1.InstancePort, ctx3)

			plugin.RefreshIpvsService(map[string]plugin.LbInfo{env.lb.ListenerUuid: env.lb, env.lb1.ListenerUuid: env.lb1}, false)

			// check ipvs config
			wait := 6 //
			time.Sleep(time.Duration(wait) * time.Second)
			ipvs, _ := plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 2).To(BeTrue(), "ipvs frond service added")
			for _, fs := range ipvs.Services {
				if fs.FrontIp == env.lb.Vip && fs.FrontPort == fmt.Sprintf("%d", env.lb.LoadBalancerPort) {
					Expect(len(fs.BackendServers) == 2).To(BeTrue(), "2 ipvs backend server added")
					for _, bs := range fs.BackendServers {
						Expect(bs.FrontIp == "192.168.2.100").To(BeTrue(), "ipvs backend server added")
						Expect(bs.FrontPort == "80" || bs.FrontPort == "81").To(BeTrue(), "ipvs backend server added")
						Expect(bs.ProtocolType == "-u").To(BeTrue(), "ipvs backend server added")
						Expect(bs.ConnectionType == "-m").To(BeTrue(), "ipvs backend server added")
						Expect(bs.Scheduler == "rr").To(BeTrue(), "ipvs backend server added")
						Expect(bs.BackendIp == "192.168.3.10" || bs.BackendIp == "192.168.3.11").To(BeTrue(), "ipvs backend server is up")
						Expect(bs.BackendPort == "8080").To(BeTrue(), "ipvs backend server added")
					}
				} else {
					Expect(len(fs.BackendServers) == 1).To(BeTrue(), "1 ipvs backend server added")
				}
			}

			// check ipvs metrics
			plugin.UpdateIpvsCounters()
			fs := plugin.GetIpvsFrontService(env.lb.ListenerUuid)
			for _, bs := range fs.BackendServers {
				cnt := bs.Counter
				Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server is up")
			}

			fs = plugin.GetIpvsFrontService(env.lb1.ListenerUuid)
			for _, bs := range fs.BackendServers {
				cnt := bs.Counter
				Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server is up")
			}

			cancel1()
			cancel2()
			cancel3()
			//wait udp server down
			time.Sleep(time.Duration(2) * time.Second)
		})

		It("ipvs: RefreshIpvsService with empty nicIps", func() {
			ctx3, cancel3 := context.WithCancel(context.Background())
			go utils.StartUdpServer(env.bs3.Ip, env.lb1.InstancePort, ctx3)

			env.lb.NicIps = []string{}
			plugin.RefreshIpvsService(map[string]plugin.LbInfo{env.lb.ListenerUuid: env.lb, env.lb1.ListenerUuid: env.lb1}, false)

			// check ipvs config
			wait := 6 //
			time.Sleep(time.Duration(wait) * time.Second)
			ipvs, _ := plugin.NewIpvsConfFromSave()
			Expect(plugin.GetIpvsFrontService(env.lb.ListenerUuid)).To(BeNil(), "lb has been deleted")
			Expect(len(ipvs.Services) == 1).To(BeTrue(), "ipvs frond service added")

			// check ipvs metrics
			plugin.UpdateIpvsCounters()
			fs := plugin.GetIpvsFrontService(env.lb.ListenerUuid)
			Expect(plugin.GetIpvsFrontService(env.lb.ListenerUuid)).To(BeNil(), "lb has been deleted")

			fs = plugin.GetIpvsFrontService(env.lb1.ListenerUuid)
			for _, bs := range fs.BackendServers {
				cnt := bs.Counter
				Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server is up")
			}

			env.lb.NicIps = []string{env.bs1.Ip, env.bs2.Ip}
			cancel3()
			//wait udp server down
			time.Sleep(time.Duration(2) * time.Second)
		})

		It("ipvs: del lb", func() {
			bs := plugin.BackendServerInfo{
				Ip:     "192.168.3.10",
				Weight: 100,
			}
			sg := plugin.ServerGroupInfo{Name: "default-server-group",
				ServerGroupUuid: "8e52bcc526074521894162aa8db73c24",
				BackendServers:  []plugin.BackendServerInfo{bs},
				IsDefault:       false,
			}
			env.lb.ServerGroups = []plugin.ServerGroupInfo{sg}
			env.lb.RedirectRules = nil

			plugin.DelIpvsService(map[string]plugin.LbInfo{env.lb.ListenerUuid: env.lb, env.lb1.ListenerUuid: env.lb1})
			
			wait := 6
			time.Sleep(time.Duration(wait) * time.Second)

			// check ipvs config
			ipvs, _ := plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 0).To(BeTrue(), "ipvs frond service added")

			// check ipvs metrics
			plugin.UpdateIpvsCounters()
			fs := plugin.GetIpvsFrontService(env.lb.ListenerUuid)
			Expect(fs).To(BeNil(), "ipvs frond service added")
		})

		It("ipvs: test destroy env", func() {
			env.DestroyBootStrap()
			env.DestroyLb()
		})
	})
})
