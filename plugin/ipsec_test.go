package plugin

import (
	"zstack-vyos/server"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = XDescribe("ipsec_test", func() {

	It("ipsec test preparing", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"ipsec_test.log", false)
		utils.CleanTestEnvForUT()
		configureAllNicsForUT()
	})

	It("test create/delete ipsec", func() {
		log.Debugf("#####test create/delete ipsec#######")
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

	It("test create native ipsec1", func() {
		cmd := &createIPsecCmd{}
		cmd.AutoRestartVpn = false

		info := &ipsecInfo{}
		info.Uuid = "sheng-test1"
		info.Vip = "172.25.3.157"
		info.LocalCidrs = []string{"192.168.100.0/24", "192.168.101.0/24", "192.168.102.0/24"}
		info.PeerAddress = "172.25.10.63"
		info.AuthKey = "1234"
		info.AuthMode = "psk"
		info.PublicNic = utils.PubNicForUT.Mac
		info.IkeAuthAlgorithm = "sha1"
		info.IkeEncryptionAlgorithm = "aes128"
		info.IkeDhGroup = 14
		info.PolicyAuthAlgorithm = "sha1"
		info.PolicyEncryptionAlgorithm = "aes128"
		info.Pfs = "dh-group14"
		info.PolicyMode = "tunnel"
		info.TransformProtocol = "esp"
		info.PeerCidrs = []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}
		info.ExcludeSnat = true
		info.LocalId = "sheng-local"
		info.RemoteId = "sheng-remote"
		info.IkeVersion = "ikev2"

		cmd.Infos = append(cmd.Infos, *info)

		info.Uuid = "sheng-test2"
		info.Vip = "172.25.3.158"
		info.LocalCidrs = []string{"192.169.100.0/24", "192.169.101.0/24", "192.169.102.0/24"}
		info.PeerAddress = "172.25.10.64"
		info.AuthKey = "5678"
		info.AuthMode = "psk"
		info.PublicNic = utils.PubNicForUT.Mac
		info.IkeAuthAlgorithm = "sha1"
		info.IkeEncryptionAlgorithm = "aes128"
		info.IkeDhGroup = 18
		info.PolicyAuthAlgorithm = "sha1"
		info.PolicyEncryptionAlgorithm = "aes128"
		info.Pfs = ""
		info.PolicyMode = "tunnel"
		info.TransformProtocol = "esp"
		info.PeerCidrs = []string{"10.1.0.0/24", "10.1.1.0/24", "10.1.2.0/24"}
		info.ExcludeSnat = true
		info.LocalId = ""
		info.RemoteId = ""
		info.IkeVersion = "ike"

		cmd.Infos = append(cmd.Infos, *info)

		for _, info := range cmd.Infos {
			err := modifyIpsecNative(&info)
			gomega.Expect(err).To(gomega.BeNil(), "create ipsec native err: %v", err)
		}

	})

	It("test update native ipsec1", func() {
		cmd := &createIPsecCmd{}
		cmd.AutoRestartVpn = false

		info := &ipsecInfo{}
		info.Uuid = "sheng-test1"
		info.Vip = "172.25.3.157"
		info.LocalCidrs = []string{"192.168.100.0/24"}
		info.PeerAddress = "172.25.10.63"
		info.AuthKey = "1234-new"
		info.AuthMode = "psk"
		info.PublicNic = utils.PubNicForUT.Mac
		info.IkeAuthAlgorithm = "sha1"
		info.IkeEncryptionAlgorithm = "aes256"
		info.IkeDhGroup = 14
		info.PolicyAuthAlgorithm = "sha1"
		info.PolicyEncryptionAlgorithm = "aes256"
		info.Pfs = "dh-group14"
		info.PolicyMode = "tunnel"
		info.TransformProtocol = "esp"
		info.PeerCidrs = []string{"10.0.0.0/24", "10.0.1.0/24"}
		info.ExcludeSnat = true
		info.LocalId = "sheng-local-new"
		info.RemoteId = "sheng-remote-new"
		info.IkeVersion = "ikev2"

		cmd.Infos = append(cmd.Infos, *info)

		for _, info := range cmd.Infos {
			err := modifyIpsecNative(&info)
			gomega.Expect(err).To(gomega.BeNil(), "update ipsec native err: %v", err)
		}
	})

	It("test delete native ipsec1", func() {
		cmd := &createIPsecCmd{}
		cmd.AutoRestartVpn = false

		info := &ipsecInfo{}
		info.Uuid = "sheng-test2"
		cmd.Infos = append(cmd.Infos, *info)

		for _, info := range cmd.Infos {
			err := deleteIpsecNative(&info)
			gomega.Expect(err).To(gomega.BeNil(), "delete ipsec native err: %v", err)
		}

	})

	It("ipsec test destroying", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"ipsec_test.log", false)
	})

})
