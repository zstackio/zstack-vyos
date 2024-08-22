package plugin

import (
	"fmt"
	"io/ioutil"
	"strings"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("lb_test", func() {

	It("LB:test prepare env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"lb_test.log", false)
		utils.CleanTestEnvForUT()
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		configureAllNicsForUT()
	})

	It("LB:test lb will delete firewall rule after start failed", func() {
		var vips []vipInfo
		vip1 := vipInfo{Ip: "100.64.1.200", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vip2 := vipInfo{Ip: "100.64.1.201", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vips = append(vips, vip1)
		vips = append(vips, vip2)
		ip1 := nicIpInfo{Ip: utils.PubNicForUT.Ip, Netmask: utils.PubNicForUT.Netmask, OwnerEthernetMac: utils.PubNicForUT.Mac}

		cmd := &setVipCmd{SyncVip: false, Vips: vips, NicIps: []nicIpInfo{ip1}}
		setVip(cmd)

		lb := &lbInfo{}
		lb.SecurityPolicyType = "TLS_CIPHER_POLICY_1_0"
		lb.LbUuid = "f2c7b2ff2f834e1ea20363f49122a3b4"
		lb.ListenerUuid = "23fb656e4f324e74a4889582104fcbf0"
		lb.InstancePort = 433
		lb.LoadBalancerPort = 433
		lb.Vip = "100.64.1.201"
		lb.NicIps = append(lb.NicIps, "192.168.100.10")
		lb.Mode = "http"
		lb.PublicNic = utils.PubNicForUT.Mac
		lb.Parameters = append(lb.Parameters,
			"balancerWeight::192.168.100.10::100",
			"connectionIdleTimeout::60",
			"Nbprocess::1",
			"balancerAlgorithm::roundrobin",
			"healthCheckTimeout::2",
			"healthCheckTarget::tcp:default",
			"maxConnection::2000000",
			"httpMode::http-server-close",
			"accessControlStatus::enable",
			"healthyThreshold::2",
			"healthCheckInterval::5",
			"unhealthyThreshold::2")

		bs := backendServerInfo{
			Ip:     "192.168.100.10",
			Weight: 100,
		}
		sg := serverGroupInfo{Name: "default-server-group",
			ServerGroupUuid: "8e52bcc526074521894162aa8db73c24",
			BackendServers:  []backendServerInfo{bs},
			IsDefault:       false,
		}
		lb.ServerGroups = []serverGroupInfo{sg}
		lb.RedirectRules = nil

		var bash utils.Bash
		bash = utils.Bash{
			Command: fmt.Sprintf("sudo chmod 222 /opt/vyatta/sbin/haproxy"),
		}
		_, _, _, _ = bash.RunWithReturn()
		bash.PanicIfError()

		defer func() {
			err := recover()
			if err != nil {
				checkLbFirewall(utils.PubNicForUT, *lb, false)
				bash = utils.Bash{
					Command: fmt.Sprintf("sudo chmod 111 /opt/vyatta/sbin/haproxy"),
				}
				_, _, _, _ = bash.RunWithReturn()
				bash.PanicIfError()

				rcmd := &removeVipCmd{Vips: vips}
				removeVip(rcmd)
			}
		}()

		setLb(*lb)
	})

	It("LB: test start lb success", func() {
		/*
		   1.mock request
		   2.simulate lb start failed
		   3.check firewall is existed
		   4.check haproxy pid
		   5.check haproxy configuration
		*/

		var vips []vipInfo
		vip1 := vipInfo{Ip: "100.64.1.200", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vip2 := vipInfo{Ip: "100.64.1.201", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vips = append(vips, vip1)
		vips = append(vips, vip2)
		ip1 := nicIpInfo{Ip: utils.PubNicForUT.Ip, Netmask: utils.PubNicForUT.Netmask, OwnerEthernetMac: utils.PubNicForUT.Mac}

		cmd := &setVipCmd{SyncVip: false, Vips: vips, NicIps: []nicIpInfo{ip1}}
		log.Debugf("setVip %+v", cmd)
		setVip(cmd)
		checkVipConfig(vips, utils.PubNicForUT, utils.NOHA)

		rcmd := &removeVipCmd{Vips: vips}
		defer func() {
			removeVip(rcmd)

		}()
		testLbSuccess()
		removeVip(rcmd)
	})

	It("LB:test enable or disable haproxy log", func() {
		var vips []vipInfo
		vip1 := vipInfo{Ip: "100.64.1.200", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vip2 := vipInfo{Ip: "100.64.1.201", Netmask: utils.PubNicForUT.Netmask, Gateway: utils.PubNicForUT.Gateway,
			OwnerEthernetMac: utils.PubNicForUT.Mac}
		vips = append(vips, vip1)
		vips = append(vips, vip2)
		ip1 := nicIpInfo{Ip: utils.PubNicForUT.Ip, Netmask: utils.PubNicForUT.Netmask, OwnerEthernetMac: utils.PubNicForUT.Mac}

		cmd := &setVipCmd{SyncVip: false, Vips: vips, NicIps: []nicIpInfo{ip1}}
		setVip(cmd)

		lb := &lbInfo{}
		lb.SecurityPolicyType = "TLS_CIPHER_POLICY_1_0"
		lb.LbUuid = "f2c7b2ff2f834e1ea20363f49122a3b4"
		lb.ListenerUuid = "23fb656e4f324e74a4889582104fcbf0"
		lb.InstancePort = 433
		lb.LoadBalancerPort = 433
		lb.Vip = "100.64.1.201"
		lb.NicIps = append(lb.NicIps, "192.168.100.10")
		lb.Mode = "http"
		lb.PublicNic = utils.PubNicForUT.Mac
		lb.Parameters = append(lb.Parameters,
			"balancerWeight::192.168.100.10::100",
			"connectionIdleTimeout::60",
			"Nbprocess::1",
			"balancerAlgorithm::roundrobin",
			"healthCheckTimeout::2",
			"healthCheckTarget::tcp:default",
			"maxConnection::2000000",
			"httpMode::http-server-close",
			"accessControlStatus::disable",
			"healthyThreshold::2",
			"healthCheckInterval::5",
			"unhealthyThreshold::2")
		bs := backendServerInfo{
			Ip:     "192.168.100.10",
			Weight: 100,
		}
		sg := serverGroupInfo{Name: "default-server-group",
			ServerGroupUuid: "8e52bcc526074521894162aa8db73c24",
			BackendServers:  []backendServerInfo{bs},
			IsDefault:       false,
		}
		lb.ServerGroups = []serverGroupInfo{sg}
		lb.RedirectRules = nil

		EnableHaproxyLog = true
		setLb(*lb)
		checkHaproxyLog(*lb, true)

		EnableHaproxyLog = false
		setLb(*lb)
		checkHaproxyLog(*lb, false)
	})

	It("LB: test refresh lb log", func() {
		testLbRefreshLbLog()
	})

	It("LB: test operate Certificate", func() {
		testCreateCertificate()
	})

	It("LB: test clean env", func() {
		utils.CleanTestEnvForUT()
	})
})

func checkHaproxyLog(lb lbInfo, isEnable bool) {
	confPath := makeLbConfFilePath(lb)
	bash := utils.Bash{
		Command: fmt.Sprintf("cat %s | grep 'log 127.0.0.1 local1'", confPath),
	}
	ret, _, _, _ := bash.RunWithReturn()
	if isEnable {
		gomega.Expect(ret).To(gomega.Equal(0), "haproxy log should enable")
	} else {
		gomega.Expect(ret).NotTo(gomega.Equal(0), "haproxy log should disable")
	}
}

func testLbSuccess() {
	lb := &lbInfo{}
	lb.LbUuid = "f2c7b2ff2f834e1ea20363f49122a3b4"
	lb.ListenerUuid = "23fb656e4f324e74a4889582104fcbf0"
	lb.InstancePort = 433
	lb.LoadBalancerPort = 433
	lb.Vip = "100.64.1.201"
	lb.NicIps = append(lb.NicIps, "192.168.100.10")
	lb.Mode = "http"
	lb.PublicNic = utils.PubNicForUT.Mac
	lb.Parameters = append(lb.Parameters,
		"balancerWeight::192.168.100.10::100",
		"connectionIdleTimeout::60",
		"Nbprocess::1",
		"balancerAlgorithm::roundrobin",
		"healthCheckTimeout::2",
		"healthCheckTarget::tcp:default",
		"maxConnection::2000000",
		"httpMode::http-server-close",
		"accessControlStatus::enable",
		"healthyThreshold::2",
		"healthCheckInterval::5",
		"unhealthyThreshold::2")

	setLb(*lb)
	checkLbFirewall(utils.PubNicForUT, *lb, true)
	delLb(*lb)
	checkLbFirewall(utils.PubNicForUT, *lb, false)
}

func testLbRefreshLbLog() {
	lbLevel := &lbLogLevelConf{}
	lbLevel.Level = "debug"

	doRefreshLogLevel(lbLevel.Level)
	checkLbLogLevel(lbLevel)
}

func checkLbLogLevel(conf *lbLogLevelConf) {
	infoFromFile, err := ioutil.ReadFile("/etc/rsyslog.d/haproxy.conf")
	gomega.Expect(err).To(gomega.BeNil(), "check lb log level fail, beacause %v", err)
	gomega.Expect(string(infoFromFile)).To(gomega.ContainSubstring(conf.Level), "check lb log level fail, beacause config file not contain debug")
}

func checkLbFirewall(nic utils.NicInfo, lb lbInfo, started bool) {
	tree := server.NewParserFromShowConfiguration().Tree
	rules := tree.Getf("firewall name %s.local rule", nic.Name)
	var bash utils.Bash
	bash = utils.Bash{
		Command: fmt.Sprintf("ps -ef|grep haproxy|grep lb-%v-listener-%v", lb.LbUuid, lb.ListenerUuid),
	}
	code, _, _, _ := bash.RunWithReturn()
	if !started {
		for _, rule := range rules.Children() {
			ruleId := rule.Name()
			if ruleId == "" {
				continue
			}

			cmd := fmt.Sprintf("firewall name %s.local rule %s description %s", nic.Name, ruleId, makeLbFirewallRuleDescription(lb))
			rule = tree.Get(cmd)
			if rule != nil {
				Fail("Failure reason")
			}
		}
	} else {
		if code == 1 {
			Fail("Failure reason")
		}
		isExistFirewallRule := false
		cmd := ""
		for _, rule := range rules.Children() {

			ruleId := rule.Name()
			if ruleId == "" {
				continue
			}

			cmd = fmt.Sprintf("firewall name %s.local rule %s description %s", nic.Name, ruleId, makeLbFirewallRuleDescription(lb))
			rule = tree.Get(cmd)
			if rule == nil {
				isExistFirewallRule = true

			}
		}
		if !isExistFirewallRule {
			Fail("Failure reason")
		}
	}
}

func testCreateCertificate() {
	certificate := &certificateInfo{}
	certificate.Certificate = `
-----BEGIN CERTIFICATE REQUEST-----
MIIC1zCCAb8CAQAwgZExCzAJBgNVBAYTAkNOMREwDwYDVQQIDAhzaGFuZ2hhaTER
MA8GA1UEBwwIc2hhbmdoYWkxETAPBgNVBAoMCG5vd3lvdWdvMQswCQYDVQQLDAJJ
VDEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMSIwIAYJKoZIhvcNAQkBFhMxMDg1
ODk2NjYzQHRlc3QuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
t8ti6F2u6bzsu5Y73iAgytPK7ATqD/TJaotkFejuiyY9ydcf9SS2J7VRuB6CiU9w
Q5m2q2D1jIFsrjzEZ9Sbn1vuWa/cFHW3w6JMUQb/5uDqwSj678B/qcFN+S1b8HPq
FYpiR8fnsBQ1sKCeyLUhM+AZaJc5x7/hcTHE7554njELmMO8cBrSPPU3AHqhbLsR
7XjcODIpcpBnt/kqmcktKdTU9iwqRXrKATUmW5bLVW8xqYCwJ0bGy80X/XG2d3Dz
eANj7nBtfCql+M8TyPC9mhMwLs5ZzYgmxnlrlVqWa0TlNSof59C94RWJwSUb+70Q
eqzYlO84lT/7NPeoFq2z+wIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAAF6KkTE
Oz4KAf1kR6EE6hiwFDOAtUywOhhlE1ZRSS3z1Qof9cwHozmEqE2Ls3FnMxX2cXxQ
Oc8JToB0tWzI0d/d58CBX4A1sOsc3t5820PeFm082A6KBm0/A2Wx/POiUGaD6/ND
4kigiH/rIazMONf72q9fVcOWXEzU6CR6UUuOWbBrigU+HaGDHGeGccdq5HXaEr7z
4GZTcKnyaKaLBA3mSXBW4i/2LNhtXjYWmfYGa6JYNLR3u+2gICZKdemRd0udUGi4
aFc8WkRCpEpHqakZW4izQXZchJDL9CGMGBUztwSqce39AiSJa0FnPDy74KcU0sTh
qdvt93J4SWSJYDE=
-----END CERTIFICATE REQUEST-----
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3y2LoXa7pvOy7
ljveICDK08rsBOoP9Mlqi2QV6O6LJj3J1x/1JLYntVG4HoKJT3BDmbarYPWMgWyu
PMRn1JufW+5Zr9wUdbfDokxRBv/m4OrBKPrvwH+pwU35LVvwc+oVimJHx+ewFDWw
oJ7ItSEz4BlolznHv+FxMcTvnnieMQuYw7xwGtI89TcAeqFsuxHteNw4MilykGe3
+SqZyS0p1NT2LCpFesoBNSZblstVbzGpgLAnRsbLzRf9cbZ3cPN4A2PucG18KqX4
zxPI8L2aEzAuzlnNiCbGeWuVWpZrROU1Kh/n0L3hFYnBJRv7vRB6rNiU7ziVP/s0
96gWrbP7AgMBAAECggEAYQ5WPL68D1Jk8Op00ufEaVdOYTR3JdXuRwU05R0MWw7m
sh+YEKxCRNXLQZ9a74ezkP8rJ3UcNgZijeApF2t+grjZNSNY5LUFRZn/EwrPN+yu
CzLI0LKmt84MjvkVA/UyOA3LuHwoLSN+9rbbIsIDtpEw2bqCGKmLM2tExAS7TU1T
3uORsQQGTBRfMouWzr6GOvrn/uHXQsIQ3PL4wfwSW2OGXBkKFw/1XHBo+Jk5VUNo
O0uWr+2XTxDC96ri+Kfgp2BTGWo07RE93yV44JjMLBTQL13iGpxvcD+L6pueSYSs
HW7lN6JJJpo0O/ldMQu3UVoyuGGfNPxDZZFe01LRgQKBgQDdRE1ryP0ctUcEUe2s
s3wKiUoc6ifbBli3XonELqgQiKFTw1qj0uKgD0tdE4ATyrgk3chXAo936i/WTZgn
v2HHjcGHmjUGGE3+vIiG4LbIHcuMoWDV6F8Wn4YpT1nO4OM1Qt5YCC/mFdS8CEFK
fbLK8FPqH837KP8l4/Pwz89RbQKBgQDUpT41/TxPCNghWdj9DOIVhgYC7lZc0/Hz
lPBdJnK+e6OxBDD9v3NDiT7XxcO8hh+TQXRHqQEbilPcqyGswTXsPv3ZD7mU5xIv
0DGK2agNW16+3ICtfjP+5aBSLRfK71DW3pFad02EDUUaQGxUydbYFaOVMw5dkPn+
2GBazroiBwKBgQCvE6xu7MnaPVXEBU+apyou7BLIbj66/3qTHSrFIGW7L2D3dkvx
9Jt9KpznONbO0kiCYzpyHoSGzbasSxlp2fT0gSXwtgPenryYI3Wjw4rdLTYyQD7v
Ar66l98AMNlO6ILfUdm8rj24QO3jGmUPHAasrRy41BGX+ghpYsVSdhwEwQKBgQC+
mRY34jHKTY0b56Kcvo1u6WA+BE8YiUiXIeqIM8wpfDzuj2kyKAYyhLP1R2f4dOec
X9DP4mYBv20Hn8RhShUBGj0B8BxRoQQmIyAk6o682icEQDR+TV5hnISk45It7W+y
CHCUe9bZA+PqcdAn93pA2LR1KPw5VZcem+dRvXYMxQKBgA2S4BZq/KTkJRpcBC2n
SzQ4wyuW+Yyz9X6aInsyBWSS40GLhFFcGRqwW3zvtJ3O4dOWCO9XWDvXU0w9S6o1
Z24AtRMp0hnhApZ8+PuunrA98eSHykB3Jfe5Le9QbiH6PXQqj+F8eKjMO2ackGgb
LILzmcP+euenar2n+ER8IJ34
-----END PRIVATE KEY-----

`
	certificate.Uuid = "996ccde3b1b64ac0952bd8002e565d6b"

	createCertificate(certificate)

	checkCertificateFile(certificate, true)

	cmd := &deleteCertificateCmd{}
	cmd.Uuid = certificate.Uuid
	deleteCertificate(cmd)

	checkCertificateFile(certificate, false)
}

func checkCertificateFile(cret *certificateInfo, create bool) interface{} {
	filePath := makeCertificatePath(cret.Uuid)

	contentByte, err := ioutil.ReadFile(filePath)

	if create {
		res := strings.Compare(string(contentByte), cret.Certificate)
		gomega.Expect(res).To(gomega.Equal(0), "create certificate failed")
	} else {
		gomega.Expect(err).NotTo(gomega.BeNil(), "delete certificate failed")
	}
	return nil
}
