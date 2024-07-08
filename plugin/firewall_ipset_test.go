package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
)

type firewallJsonData struct {
	Group    string   `json:"group"`
	InfoList []myCase `json:"infolist"`
}
type myCase struct {
	Title   string    `json:"title"`
	CmdList []cmdType `json:"cmdlist"`
}
type cmdType struct {
	Path    string      `json:"path"`
	Msgbody interface{} `json:"msgbody"`
}

var _ = Describe("firewall_ipset_test", func() {

	Context("[IPTABLES]FIREWALL: env prepare", func() {
		It("firewall_ipset prepare", func() {
			utils.InitLog(utils.GetVyosUtLogDir()+"firewall_ipset_test.log", false)
			utils.CleanTestEnvForUT()
			SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
			utils.SetSkipVyosIptablesForUT(true)

			nicCmd := &configureNicCmd{}
			nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
			nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
			configureNic(nicCmd)
		})
	})

	Context("[IPTABLES]FIREWALL: test IpSet use new method", func() {
		testFirewallCaseData := &firewallJsonData{}
		err := loadTestJsonFile("firewall_data.json", &testFirewallCaseData)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("loadTestJsonFile Expect BeNil, But %s", err))

		for _, myCase := range testFirewallCaseData.InfoList {
			myCase := myCase
			It("#### CASE TITLE: "+myCase.Title, func() {
				err := parseMessageAndRunTestCase(myCase.CmdList)
				gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("parseTestMessage Expect BeNil, But %s", err))
			})
		}
	})
	Context("[IPTABLES]FIREWALL: env destroy", func() {
		It("[IPTABLES]FIREWALL : firewall_ipset destroying env", func() {
			utils.CleanTestEnvForUT()
		})
	})
})

func checkAPIFWCreateRule(cmd *createRuleCmd) error {
	gomega.Expect(cmd).NotTo(gomega.BeNil(), fmt.Sprintf("checkAPIFWCreateRule: Arg Expect NoT BeNil, But %+v", cmd))
	err := createRule(cmd)
	gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("createRule: Expect Return Nil, But %+v", err))

	checkTestCreateIpset(cmd)

	return nil
}
func checkAPIFWDeleteRule(cmd *deleteRuleCmd) error {
	gomega.Expect(cmd).NotTo(gomega.BeNil(), fmt.Sprintf("checkAPIFWDeleteRule: Arg Expect NoT BeNil, But %+v", cmd))
	err := deleteRule(cmd)
	gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("deleteRule: Expect Return Nil, But %+v", err))

	checkTestDeleteIpset(cmd)

	return nil
}
func checkAPIFWApplyRuleSetChangese(cmd *applyRuleSetChangesCmd) error {
	gomega.Expect(cmd).NotTo(gomega.BeNil(), fmt.Sprintf("checkAPIFWApplyRuleSetChangese: Arg Expect NoT BeNil, But %+v", cmd))
	err := applyRuleSetChanges(cmd)
	gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("applyRuleSetChanges: Expect Return Nil, But %+v", err))

	checkTestIpsetRuleSetChange(cmd)

	return nil
}
func checkAPIFWChangeStateRule(cmd *changeRuleStateCmd) error {
	gomega.Expect(cmd).NotTo(gomega.BeNil(), fmt.Sprintf("checkAPIFWChangeStateRule: Arg Expect NoT BeNil, But %+v", cmd))
	err := changeRuleState(cmd)
	gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("changeRuleState: Expect Return Nil, But %+v", err))

	return nil
}
func checkAPIFWApplyRule(cmd *applyUserRuleCmd) error {
	gomega.Expect(cmd).NotTo(gomega.BeNil(), fmt.Sprintf("checkAPIFWApplyRule: Arg Expect NoT BeNil, But %+v", cmd))
	err := applyUserRules(cmd)
	gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("applyUserRules: Expect Return Nil, But %+v", err))

	checkTestIpsetApplyRule(cmd)
	return nil
}

func checkTestIpsetApplyRule(cmd *applyUserRuleCmd) error {
	for _, ref := range cmd.Refs {
		nicName, err := utils.GetNicNameByMac(ref.Mac)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("GetNicNameByMac: Expect Return Nil, But %+v", err))
		checkRulesIpset(nicName, ref.Forward, ref.RuleSetInfo.Rules, nil)
	}
	return nil
}

func checkTestIpsetRuleSetChange(cmd *applyRuleSetChangesCmd) error {
	for _, ref := range cmd.Refs {
		nicName, err := utils.GetNicNameByMac(ref.Mac)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("GetNicNameByMac: Expect Return Nil, But %+v", err))
		checkRulesIpset(nicName, ref.Forward, cmd.NewRules, nil)
	}

	return nil
}

func checkRulesIpset(nicName string, forward string, newRules []ruleInfo, deleteRules []ruleInfo) error {
	ruleSetName := buildRuleSetName(nicName, forward)
	for _, rule := range newRules {
		srcSetName := rule.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX)
		srcIpSet := utils.NewIPSet(srcSetName, utils.IPSET_TYPE_HASH_NET)
		if strings.ContainsAny(rule.SourceIp, IP_SPLIT) && rule.State == "enable" {
			ipSetExist := srcIpSet.IsExist()
			gomega.Expect(ipSetExist).To(gomega.BeTrue(), fmt.Sprintf("IpSet[%s] Expect Exist, But %+v", srcSetName, ipSetExist))
			tmpIpSet := createIpsetAndSetNet(srcSetName, rule.SourceIp)
			gomega.Expect(tmpIpSet).NotTo(gomega.BeNil(), fmt.Sprintf("tmpIpSet[%s] Expect Create, But %+v", tmpIpSet, ipSetExist))
			checkIpsetIsEqual(srcIpSet, tmpIpSet)
		} else {
			ipSetExist := srcIpSet.IsExist()
			gomega.Expect(ipSetExist).To(gomega.BeFalse(), fmt.Sprintf("IpSet[%s] Expect Not Exist, But %v", srcSetName, ipSetExist))
		}

		dstSetName := rule.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX)
		dstIpSet := utils.NewIPSet(dstSetName, utils.IPSET_TYPE_HASH_NET)
		if strings.ContainsAny(rule.DestIp, IP_SPLIT) && rule.State == "enable" {
			ipSetExist := dstIpSet.IsExist()
			gomega.Expect(ipSetExist).To(gomega.BeTrue(), fmt.Sprintf("IpSet[%s] Expect Exist, But %+v", dstSetName, ipSetExist))
			tmpIpSet := createIpsetAndSetNet(dstSetName, rule.DestIp)
			gomega.Expect(tmpIpSet).NotTo(gomega.BeNil(), fmt.Sprintf("tmpIpSet[%s] Expect Create, But %+v", tmpIpSet, ipSetExist))
			checkIpsetIsEqual(dstIpSet, tmpIpSet)
		} else {
			ipSetExist := dstIpSet.IsExist()
			gomega.Expect(ipSetExist).To(gomega.BeFalse(), fmt.Sprintf("IpSet[%s] Expect Not Exist, But %v", dstSetName, ipSetExist))
		}
	}

	for _, rule := range deleteRules {
		srcSetName := rule.makeGroupName(ruleSetName, FIREWALL_RULE_SOURCE_GROUP_SUFFIX)
		srcIpSet := utils.NewIPSet(srcSetName, utils.IPSET_TYPE_HASH_NET)
		if strings.ContainsAny(rule.SourceIp, IP_SPLIT) && rule.State == "enable" {
			ipSetExist := srcIpSet.IsExist()
			gomega.Expect(ipSetExist).To(gomega.BeFalse(), fmt.Sprintf("IpSet[%s] Expect Not Exist, But %v", srcSetName, ipSetExist))
		}

		dstSetName := rule.makeGroupName(ruleSetName, FIREWALL_RULE_DEST_GROUP_SUFFIX)
		dstIpSet := utils.NewIPSet(dstSetName, utils.IPSET_TYPE_HASH_NET)
		if strings.ContainsAny(rule.DestIp, IP_SPLIT) && rule.State == "enable" {
			ipSetExist := dstIpSet.IsExist()
			gomega.Expect(ipSetExist).To(gomega.BeFalse(), fmt.Sprintf("IpSet[%s] Expect Not Exist, But %v", dstSetName, ipSetExist))
		}
	}
	return nil
}
func checkTestDeleteIpset(cmd *deleteRuleCmd) error {
	nicName, err := utils.GetNicNameByMac(cmd.Ref.Mac)
	gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("GetNicNameByMac: Expect Return Nil, But %+v", err))

	checkRulesIpset(nicName, cmd.Ref.Forward, nil, cmd.Ref.RuleSetInfo.Rules)

	return nil
}

func checkTestCreateIpset(cmd *createRuleCmd) error {
	nicName, err := utils.GetNicNameByMac(cmd.Ref.Mac)
	gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("GetNicNameByMac: Expect Return Nil, But %+v", err))

	checkRulesIpset(nicName, cmd.Ref.Forward, cmd.Ref.RuleSetInfo.Rules, nil)

	return nil
}

func checkIpsetIsEqual(origSet *utils.IpSet, tmpSet *utils.IpSet) error {
	bash := utils.Bash{
		Command: fmt.Sprintf("ipset list %s | sed -n '/^[0-9]/p' | sort", origSet.Name),
		Sudo:    true,
	}
	_, origOutString, _, err := bash.RunWithReturn()
	gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("ipset list [%+v] error", err))

	bash = utils.Bash{
		Command: fmt.Sprintf("ipset list %s | sed -n '/^[0-9]/p' | sort", tmpSet.Name),
		Sudo:    true,
	}
	_, tmpOutString, _, err := bash.RunWithReturn()
	gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("ipset list [%+v] error", err))

	tmpSet.Destroy()

	isEqual := strings.EqualFold(origOutString, tmpOutString)
	gomega.Expect(isEqual).To(gomega.BeTrue(), fmt.Sprintf("orig ipset[%s] check error", origSet.Name))

	return nil
}

func getTestMessageBody(message interface{}, cmd interface{}) error {
	gomega.Expect(message).NotTo(gomega.BeNil(), fmt.Sprintf("getTestMessageBody: Arg Expect Not BeNil, But %+v", message))
	gomega.Expect(cmd).NotTo(gomega.BeNil(), fmt.Sprintf("getTestMessageBody: Arg Expect Not BeNil, But %+v", cmd))

	jsonData, err := json.Marshal(message)
	gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("Message Marshal Expect return Nil , But %+v", err))

	jsonData = bytes.Replace(jsonData, []byte("PubNicForUT.Mac"), []byte(utils.PubNicForUT.Mac), -1)
	jsonData = bytes.Replace(jsonData, []byte("PrivateNicsForUT[0].Mac"), []byte(utils.PrivateNicsForUT[0].Mac), -1)
	jsonData = bytes.Replace(jsonData, []byte("PrivateNicsForUT[1].Mac"), []byte(utils.PrivateNicsForUT[1].Mac), -1)

	err = json.Unmarshal(jsonData, cmd)
	gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("Message Unmarshal Expect Return Nil , But %+v", err))

	return nil
}

func parseMessageAndRunTestCase(cmdList []cmdType) error {
	gomega.Expect(cmdList).NotTo(gomega.BeNil(), fmt.Sprintf("cmdList Expect Not BeNil, But %+v", cmdList))

	for _, cmdTypeInstance := range cmdList {
		gomega.Expect(cmdTypeInstance.Path).NotTo(gomega.BeNil(), fmt.Sprintf("cmdTypeInstance.Path Expect Not BeNil, But %+v", cmdTypeInstance.Path))

		switch cmdTypeInstance.Path {
		case "/fw/create/rule":
			cmd := createRuleCmd{}
			err := getTestMessageBody(cmdTypeInstance.Msgbody, &cmd)
			gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("getTestMessageBody Expect Return Nil , But %+v", err))

			checkAPIFWCreateRule(&cmd)

		case "/fw/delete/rule":
			cmd := deleteRuleCmd{}
			err := getTestMessageBody(cmdTypeInstance.Msgbody, &cmd)
			gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("getTestMessageBody Expect Return Nil , But %+v", err))

			checkAPIFWDeleteRule(&cmd)

		case "/fw/apply/ruleSet/changes":
			cmd := applyRuleSetChangesCmd{}
			err := getTestMessageBody(cmdTypeInstance.Msgbody, &cmd)
			gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("getTestMessageBody Expect Return Nil , But %+v", err))

			checkAPIFWApplyRuleSetChangese(&cmd)

		case "/fw/changeState/rule":
			cmd := changeRuleStateCmd{}
			err := getTestMessageBody(cmdTypeInstance.Msgbody, &cmd)
			gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("getTestMessageBody Expect Return Nil , But %+v", err))

			checkAPIFWChangeStateRule(&cmd)

		case "/fw/apply/rule":
			cmd := applyUserRuleCmd{}
			err := getTestMessageBody(cmdTypeInstance.Msgbody, &cmd)
			gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("getTestMessageBody Expect return Nil , But %+v", err))

			checkAPIFWApplyRule(&cmd)
		default:
			return fmt.Errorf("Meaasge path is no defined")
		}
		fmt.Printf("Run Cmd Path : %s, Check OK ...\n", cmdTypeInstance.Path)
	}

	return nil
}

func loadTestJsonFile(filename string, jsonType interface{}) error {
	if filename == "" {
		return fmt.Errorf("loadTestJsonFile: filename is null")
	}
	testConfigData, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("loadTestJsonFile: read file %s", err)
	}
	err = json.Unmarshal(testConfigData, jsonType)
	if err != nil {
		return fmt.Errorf("loadTestJsonFile: json data %s", err)
	}

	return nil
}
