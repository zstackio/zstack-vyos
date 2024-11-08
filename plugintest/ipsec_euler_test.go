package plugintest

import (
	. "github.com/onsi/ginkgo/v2"
	"zstack-vyos/plugin"
)

var _ = Describe("euler22.03 ipsec test", func() {
	Context("vpc ipsec test", func() {
		env := NewVpcIpv4Env()
		It("ipsec_euler :test prepare env", func() {
			env.SetupBootStrap()
			env.SetupIpsec()
		})

		It("ipsec_euler: CreateIPsecConnection", func() {
			env.AddPeerAddr("ut-pub", "192.168.2.102/24")
			cmd := plugin.CreateIPsecCmd{
				Infos:          []plugin.IpsecInfo{env.ipsec1},
				AutoRestartVpn: false,
			}
			plugin.CreateIPsecConnection(&cmd)
		})

		It("ipsec_euler: DeleteIPsecConnection", func() {
			cmd := plugin.DeleteIPsecCmd{
				Infos: []plugin.IpsecInfo{env.ipsec1},
			}
			plugin.DeleteIPsecConnection(&cmd)
		})

		It("ipsec_euler: ", func() {
			cmd := plugin.SyncIPsecCmd{
				Infos:          []plugin.IpsecInfo{env.ipsec1},
				AutoRestartVpn: false,
			}
			plugin.SyncIPsecConnection(&cmd)
		})

		It("ipsec_euler: DeleteIPsecConnection", func() {
			cmd := plugin.DeleteIPsecCmd{
				Infos: []plugin.IpsecInfo{env.ipsec1},
			}
			plugin.DeleteIPsecConnection(&cmd)
		})

		It("ipsec_euler: test destroy env", func() {
			env.DestroyIpsec()
			env.DestroyBootStrap()
		})
	})
})
