package plugintest

import (
	. "github.com/onsi/ginkgo/v2"
	"zstack-vyos/plugin"
)

var _ = Describe("snat test", func() {
	Context("snat iptables test", func() {
		env := NewVpcIpv4Env()
		It("ipsec_euler :test prepare env", func() {
			env.SetupBootStrap()
			env.SetupSnat()
		})

		It("snat SetSnat", func() {

			cmd := plugin.SetSnatCmd{
				Snat: env.snat1,
			}
			plugin.SetSnat(&cmd)

			/* TODO: check result */

			cmd = plugin.SetSnatCmd{
				Snat: env.snat2,
			}
			plugin.SetSnat(&cmd)

			/* TODO: check result */
		})

		It("snat SetSnat", func() {
			cmd := plugin.RemoveSnatCmd{
				NatInfo: []plugin.SnatInfo{env.snat1, env.snat2},
			}
			plugin.RemoveSnat(&cmd)
			/* TODO: check result */
		})

		It("snat SyncSnat", func() {
			cmd := plugin.SyncSnatCmd{
				Snats:  []plugin.SnatInfo{env.snat1, env.snat2, env.snat3, env.snat4},
				Enable: true,
			}
			plugin.SyncSnat(&cmd)
			/* TODO: check result */

			cmd = plugin.SyncSnatCmd{
				Snats:  []plugin.SnatInfo{env.snat1, env.snat2},
				Enable: true,
			}
			plugin.SyncSnat(&cmd)

			/* TODO: check result */
		})

		It("snat SetSnatStateCmd", func() {
			cmd := plugin.SetSnatStateCmd{
				Snats:  []plugin.SnatInfo{env.snat1, env.snat2, env.snat3, env.snat4},
				Enable: true,
			}
			plugin.SetSnatState(&cmd)
			/* TODO: check result */

			cmd = plugin.SetSnatStateCmd{
				Snats:  []plugin.SnatInfo{env.snat1, env.snat2},
				Enable: false,
			}
			plugin.SetSnatState(&cmd)

			/* TODO: check result */
		})

		It("ipsec_euler: test destroy env", func() {
			env.DestroyBootStrap()
		})
	})
})
