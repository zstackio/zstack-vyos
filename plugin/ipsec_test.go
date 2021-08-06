package plugin

import (
    . "github.com/onsi/ginkgo"
    "github.com/zstackio/zstack-vyos/server"
    "github.com/zstackio/zstack-vyos/utils"
    "github.com/zstackio/zstack-vyos/utils/test"
)

func setTestIpsecEnv()  {
    utils.InitLog(test.VYOS_UT_LOG_FOLDER + "ipsec_test.log", false)
}

var _ = Describe("ipsec_test", func() {
    var nicCmd *configureNicCmd
    BeforeEach(func() {
        setTestIpsecEnv()
        nicCmd = &configureNicCmd{}
    })

    It("test create ipsec", func() {
        nicCmd.Nics = append(nicCmd.Nics, test.PubNicForUT)
        configureNic(nicCmd)
        cmd := &createIPsecCmd{}
        info := &ipsecInfo{}

        info.Uuid = "b7d5e47f11124661bf59905dfafe99a2"
        info.Vip = "172.24.3.157"
        info.LocalCidrs = []string{"192.169.100.0/24"}
        info.PeerAddress = "172.25.10.63"
        info.AuthKey = "1234"
        info.AuthMode = "psk"
        info.PublicNic = test.PubNicForUT.Mac
        info.IkeAuthAlgorithm = "sha1"
        info.IkeEncryptionAlgorithm = "aes128"
        info.PolicyAuthAlgorithm = "sha1"
        info.PolicyEncryptionAlgorithm = "aes128"
        info.Pfs = "dh-group2"
        info.PolicyMode = "tunnel"
        info.TransformProtocol = "esp"
        info.PeerCidrs = []string{"172.25.10.63/24"}
        info.ExcludeSnat = true

        cmd.AutoRestartVpn = false
        cmd.Infos = []ipsecInfo{*info}

        vyos := server.NewParserFromShowConfiguration()
        tree := vyos.Tree
        for _, info := range cmd.Infos {
            createIPsec(tree, info)
        }

    })

    It("test delete ipsec", func() {
        nicCmd.Nics = append(nicCmd.Nics, test.PubNicForUT)
        configureNic(nicCmd)
        cmd := &createIPsecCmd{}
        info := &ipsecInfo{}

        info.Uuid = "b7d5e47f11124661bf59905dfafe99a2"
        info.Vip = "172.24.3.157"
        info.LocalCidrs = []string{"192.169.100.0/24"}
        info.PeerAddress = "172.25.10.63"
        info.AuthKey = "1234"
        info.AuthMode = "psk"
        info.PublicNic = test.PubNicForUT.Mac
        info.IkeAuthAlgorithm = "sha1"
        info.IkeEncryptionAlgorithm = "aes128"
        info.PolicyAuthAlgorithm = "sha1"
        info.PolicyEncryptionAlgorithm = "aes128"
        info.Pfs = "dh-group2"
        info.PolicyMode = "tunnel"
        info.TransformProtocol = "esp"
        info.PeerCidrs = []string{"172.25.10.63/24"}
        info.ExcludeSnat = true

        cmd.AutoRestartVpn = false
        cmd.Infos = []ipsecInfo{*info}

        vyos := server.NewParserFromShowConfiguration()
        tree := vyos.Tree
        for _, info := range cmd.Infos {
            createIPsec(tree, info)
        }
        tree.Apply(false)

        for _, info := range cmd.Infos {
            deleteIPsec(tree, info)
        }
        tree.Apply(false)
    })

    It("test update ipsec", func() {
        nicCmd.Nics = append(nicCmd.Nics, test.PubNicForUT)
        configureNic(nicCmd)
        cmd := &createIPsecCmd{}
        info := &ipsecInfo{}

        info.Uuid = "b7d5e47f11124661bf59905dfafe99a2"
        info.Vip = "172.24.3.157"
        info.LocalCidrs = []string{"192.169.100.0/24"}
        info.PeerAddress = "172.25.10.63"
        info.AuthKey = "1234"
        info.AuthMode = "psk"
        info.PublicNic = test.PubNicForUT.Mac
        info.IkeAuthAlgorithm = "sha1"
        info.IkeEncryptionAlgorithm = "aes128"
        info.PolicyAuthAlgorithm = "sha1"
        info.PolicyEncryptionAlgorithm = "aes128"
        info.Pfs = "dh-group2"
        info.PolicyMode = "tunnel"
        info.TransformProtocol = "esp"
        info.PeerCidrs = []string{"172.25.10.63/24"}
        info.ExcludeSnat = true

        cmd.AutoRestartVpn = false
        cmd.Infos = []ipsecInfo{*info}

        vyos := server.NewParserFromShowConfiguration()
        tree := vyos.Tree
        for _, info := range cmd.Infos {
            createIPsec(tree, info)
        }
        tree.Apply(false)

        info.State = "false"
        info.ModifiedItems = []string{"State"}
        for _, info := range cmd.Infos {
            updateIPsecConnectionState(tree, info)
        }
    })
})