package plugin

import (
    log "github.com/Sirupsen/logrus"
    . "github.com/onsi/ginkgo"
    "github.com/zstackio/zstack-vyos/server"
    "github.com/zstackio/zstack-vyos/utils"
)

func setTestIpsecEnv()  {
    utils.InitLog(utils.VYOS_UT_LOG_FOLDER + "ipsec_test.log", false)
}

var _ = Describe("ipsec_test", func() {
    var nicCmd *configureNicCmd
    
    It("ipsec test preparing", func() {
        setTestIpsecEnv()
        nicCmd = &configureNicCmd{}
    })

    It("test create/delete ipsec", func() {
        log.Debugf("#####test create/delete ipsec#######")
        nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
        configureNic(nicCmd)
        cmd := &createIPsecCmd{}
        info := &ipsecInfo{}

        info.Uuid = "b7d5e47f11124661bf59905dfafe99a2"
        info.Vip = "172.24.3.157"
        info.LocalCidrs = []string{"192.169.100.0/24"}
        info.PeerAddress = "172.25.10.63"
        info.AuthKey = "1234"
        info.AuthMode = "psk"
        info.PublicNic = utils.PubNicForUT.Mac
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
    
        log.Debugf("#####test create ipsec#######")
        vyos := server.NewParserFromShowConfiguration()
        tree := vyos.Tree
        for _, info := range cmd.Infos {
            createIPsec(tree, info)
        }
        tree.Apply(false)
    
        log.Debugf("#####test delete ipsec#######")
        vyos = server.NewParserFromShowConfiguration()
        for _, info := range cmd.Infos {
            deleteIPsec(tree, info)
        }
        tree.Apply(false)
    
        restoreIpRuleForMainRouteTable()
    })
    
    It("test update ipsec", func() {
        log.Debugf("#####test update ipsec#######")
        nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
        configureNic(nicCmd)
        cmd := &createIPsecCmd{}
        info := &ipsecInfo{}

        info.Uuid = "b7d5e47f11124661bf59905dfafe99a2"
        info.Vip = "172.24.3.157"
        info.LocalCidrs = []string{"192.169.100.0/24"}
        info.PeerAddress = "172.25.10.63"
        info.AuthKey = "1234"
        info.AuthMode = "psk"
        info.PublicNic = utils.PubNicForUT.Mac
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
    
        log.Debugf("#####test update ipsec start #######")
        vyos = server.NewParserFromShowConfiguration()
        info.State = "false"
        info.ModifiedItems = []string{"State"}
        for _, info := range cmd.Infos {
            updateIPsecConnectionState(tree, info)
        }
        log.Debugf("#####test update ipsec end #######")
        
        tree = server.NewParserFromShowConfiguration().Tree
        deleteIPsec(tree, *info)
        tree.Apply(false)
    
        restoreIpRuleForMainRouteTable()
    })
    
    It("ipsec test destroying", func() {
        nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
        removeNic(nicCmd)
    })
    
})