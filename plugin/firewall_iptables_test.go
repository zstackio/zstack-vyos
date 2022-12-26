package plugin

import (
	"fmt"
	"strings"

	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	"github.com/zstackio/zstack-vyos/utils"
)

var _ = Describe("firewall_iptables_test", func() {

	//var ruleInfo1, ruleInfo2, ruleInfo
	It("[IPTABLES]FIREWALL : prepare", func() {
		eipMap = make(map[string]eipInfo, EipInfoMaxSize)
		utils.InitLog(utils.VYOS_UT_LOG_FOLDER+"firewall_iptables_test.log", false)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		utils.SetSkipVyosIptablesForUT(true)

		nicCmd := &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		configureNic(nicCmd)
	})

	/* get firewall */
	It("[IPTABLES]FIREWALL : get firewall", func() {
		By("####test get private nic firewall #######")

		// in ruleset of pri nic will permit through  eip group
		// in ruleset of pub nic will permit through  eip group
		ipInPubL3, _ := utils.GetFreePubL3Ip()
		eip1 := eipInfo{VipIp: ipInPubL3, PublicMac: utils.PubNicForUT.Mac,
			GuestIp: "192.168.1.200", PrivateMac: utils.PrivateNicsForUT[0].Mac,
			SnatInboundTraffic: false}
		cmd1 := setEipCmd{Eip: eip1}
		log.Debugf("createEip eip1: %+v before get firewall", eip1)
		createEip(&cmd1)
		checkSyncEipByIptables(eip1)

		nicInfo := nicTypeInfo{Mac: utils.PrivateNicsForUT[0].Mac, NicType: "private"}
		gcmd := getConfigCmd{NicTypeInfos: []nicTypeInfo{nicInfo}}
		rsp := getFirewallConfig(&gcmd)
		grsp, _ := rsp.(getConfigRsp)

		log.Debugf("get firewall: %+v", grsp.Refs)
		checkDefaultNicRules(nicInfo, grsp.Refs)
		checkEipRulesInChain(false, nicInfo, grsp.Refs)

		By("####test get public nic firewall #######")
		nicInfo = nicTypeInfo{Mac: utils.PubNicForUT.Mac, NicType: "public"}
		gcmd = getConfigCmd{NicTypeInfos: []nicTypeInfo{nicInfo}}
		rsp = getFirewallConfig(&gcmd)
		grsp, _ = rsp.(getConfigRsp)

		log.Debugf("get firewall: %+v", grsp.Refs)
		checkDefaultNicRules(nicInfo, grsp.Refs)
		checkEipRulesInChain(true, nicInfo, grsp.Refs)

		eipCmd := removeEipCmd{Eip: eip1}
		removeEip(&eipCmd)
	})

	/* when apply a ruleset to vpc interface will call this api: applyRuleSetChanges  */
	It("[IPTABLES]FIREWALL : test applyRuleSetChanges", func() {
		ruleInfo1 := ruleInfo{
			SourceIp: "192.168.1.100,192.168.101.0/24,192.168.30.10-192.168.30.20", DestIp: "192.168.1.101,192.168.201.0/24,192.168.30.30-192.168.30.40",
			State:     "enable",
			IsDefault: false, RuleNumber: 1110,
			AllowStates: "new,established,invalid,related",
			Protocol:    "all", Action: "accept"}

		ruleInfo2 := ruleInfo{
			SourceIp: "192.168.2.100", DestIp: "192.168.2.101",
			DestPort: "1000-1007", SourcePort: "10000-10010",
			State:     "enable",
			IsDefault: false, RuleNumber: 1002,
			AllowStates: "established,related",
			Tcp:         "SYN,ACK",
			Protocol:    "tcp", Action: "drop"}

		ruleInfo3 := ruleInfo{
			SourceIp: "192.168.3.100,192.168.3.101, 192.168.3.102", DestIp: "192.168.103.100,192.168.103.101, 192.168.103.102",
			DestPort: "1000,1002,1004,100-200", SourcePort: "1000,1002,1004,100-200",
			State:     "enable",
			IsDefault: false, RuleNumber: 1003,
			Protocol: "udp", Action: "reject"}

		ruleInfo4 := ruleInfo{
			SourceIp: "192.168.104.0/24", DestIp: "192.168.204.0/24",
			State:     "enable",
			IsDefault: false, RuleNumber: 1010,
			Protocol: "icmp", Action: "accept"}

		ruleInfo5 := ruleInfo{
			SourceIp: "192.168.5.100", DestIp: "192.168.5.101",
			DestPort: "1000", SourcePort: "10000",
			State:     "enable",
			IsDefault: false, RuleNumber: 2001,
			Protocol: "tcp", Action: "drop"}

		ruleInfo6 := ruleInfo{
			SourceIp: "10.1.1.1-10.1.1.10", DestIp: "20.1.1.1-20.1.1.10",
			DestPort: "100-200,300,400-500", SourcePort: "150-250,350,450-550",
			State:     "enable",
			IsDefault: false, RuleNumber: 1122,
			Protocol: "udp", Action: "accept",
		}

		ruleInfo7 := ruleInfo{
			SourceIp: "10.1.1.1-10.1.1.10", DestIp: "20.1.1.1-20.1.1.10",
			DestPort: "100-200,300,400-500", SourcePort: "150-250,350,450-550",
			State:     "enable",
			IsDefault: false, RuleNumber: 1123,
			Protocol: "udp", Action: "accept",
		}

		rules := []ruleInfo{ruleInfo1, ruleInfo2, ruleInfo3, ruleInfo4, ruleInfo5, ruleInfo6, ruleInfo7}

		ethRuleSetRef1 := ethRuleSetRef{
			Mac:         utils.PrivateNicsForUT[0].Mac,
			Forward:     FIREWALL_DIRECTION_IN,
			RuleSetInfo: ruleSetInfo{ActionType: "accept"},
		}
		ethRuleSetRef2 := ethRuleSetRef{
			Mac:         utils.PubNicForUT.Mac,
			Forward:     FIREWALL_DIRECTION_OUT,
			RuleSetInfo: ruleSetInfo{ActionType: "reject"},
		}
		refs := []ethRuleSetRef{ethRuleSetRef1, ethRuleSetRef2}
		ruleSetName1 := buildRuleSetName(utils.PrivateNicsForUT[0].Name, FIREWALL_DIRECTION_IN)
		ruleSetName2 := buildRuleSetName(utils.PubNicForUT.Name, FIREWALL_DIRECTION_OUT)

		By("####test applyRuleSetChanges attach ruleset to interface #######")
		acm1 := &attachRuleSetCmd{Ref: ethRuleSetRef1}
		attachRuleSet(acm1)
		// check default rule
		checkDefaultAction(ruleSetName1, "accept")
		acm2 := &attachRuleSetCmd{Ref: ethRuleSetRef2}
		attachRuleSet(acm2)
		// check default rule
		checkDefaultAction(ruleSetName2, "reject")

		By("####test applyRuleSetChanges add new rules #######")
		cmd := applyRuleSetChangesCmd{Refs: refs, NewRules: rules}
		err := applyRuleSetChanges(&cmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("firewall rule apply ruleset change failed: %+v", err))
		checkIptableRule(ruleSetName1, rules, false)
		checkIptableRule(ruleSetName2, rules, false)

		By("####test applyRuleSetChanges add new rules again #######")
		cmd = applyRuleSetChangesCmd{Refs: refs, NewRules: rules}
		err = applyRuleSetChanges(&cmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("firewall rule apply ruleset change failed: %+v", err))
		checkIptableRule(ruleSetName1, rules, false)
		checkIptableRule(ruleSetName2, rules, false)

		By("####test applyRuleSetChanges remove rules #######")
		cmd = applyRuleSetChangesCmd{Refs: refs, DeleteRules: rules}
		err = applyRuleSetChanges(&cmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("firewall rule apply ruleset change failed: %+v", err))
		checkIptableRule(ruleSetName1, rules, true)
		checkIptableRule(ruleSetName2, rules, true)

		By("####test applyRuleSetChanges remove rules again #######")
		cmd = applyRuleSetChangesCmd{Refs: refs, DeleteRules: rules}
		err = applyRuleSetChanges(&cmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("firewall rule apply ruleset change failed: %+v", err))
		checkIptableRule(ruleSetName1, rules, true)
		checkIptableRule(ruleSetName2, rules, true)

		By("####test applyRuleSetChanges change rule state #######")
		// add rule set rules
		cmd = applyRuleSetChangesCmd{Refs: refs, NewRules: rules}
		err = applyRuleSetChanges(&cmd)

		// change rule state and apply
		ruleInfo7Copy := ruleInfo7
		ruleInfo7Copy.State = "disable"
		rulesCopy := []ruleInfo{ruleInfo1, ruleInfo2, ruleInfo3, ruleInfo4, ruleInfo5, ruleInfo6, ruleInfo7Copy}
		cmd = applyRuleSetChangesCmd{Refs: refs, NewRules: rulesCopy, DeleteRules: []ruleInfo{ruleInfo7}}
		err = applyRuleSetChanges(&cmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("firewall rule apply ruleset change failed: %+v", err))
		checkIptableRuleByRuleNum(ruleSetName1, []ruleInfo{ruleInfo7}, true)
		checkIptableRuleByRuleNum(ruleSetName2, []ruleInfo{ruleInfo7}, true)
		checkIptableRule(ruleSetName1, []ruleInfo{ruleInfo1, ruleInfo2, ruleInfo3, ruleInfo4, ruleInfo5, ruleInfo6}, false)
		checkIptableRule(ruleSetName2, []ruleInfo{ruleInfo1, ruleInfo2, ruleInfo3, ruleInfo4, ruleInfo5, ruleInfo6}, false)

		// change rule state and apply to only in direction
		ruleInfo6Copy := ruleInfo6
		ruleInfo6Copy.State = "disable"
		rulesCopy = []ruleInfo{ruleInfo1, ruleInfo2, ruleInfo3, ruleInfo4, ruleInfo5, ruleInfo6Copy}
		refs = []ethRuleSetRef{ethRuleSetRef1}
		cmd = applyRuleSetChangesCmd{Refs: refs, NewRules: rulesCopy, DeleteRules: []ruleInfo{ruleInfo6}}
		err = applyRuleSetChanges(&cmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("firewall rule apply ruleset change failed: %+v", err))
		checkIptableRuleByRuleNum(ruleSetName1, []ruleInfo{ruleInfo6}, true)
		checkIptableRuleByRuleNum(ruleSetName2, []ruleInfo{ruleInfo6}, false)
		checkIptableRule(ruleSetName1, []ruleInfo{ruleInfo1, ruleInfo2, ruleInfo3, ruleInfo4, ruleInfo5}, false)
		checkIptableRule(ruleSetName2, []ruleInfo{ruleInfo1, ruleInfo2, ruleInfo3, ruleInfo4, ruleInfo5, ruleInfo6}, false)

		refs = []ethRuleSetRef{ethRuleSetRef1, ethRuleSetRef2}
		cmd = applyRuleSetChangesCmd{Refs: refs, DeleteRules: rules}
		err = applyRuleSetChanges(&cmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("firewall rule apply ruleset change failed: %+v", err))
		checkIptableRule(ruleSetName1, rules, true)
		checkIptableRule(ruleSetName2, rules, true)
	})

	/* when reconnect/restart vpc router, all rule need to be re-installed, call this api: applyUserRules  */
	It("[IPTABLES]FIREWALL : test applyUserRules", func() {
		ruleInfo1 := ruleInfo{
			SourceIp: "192.168.1.100,192.168.101.0/24,192.168.10.1-192.168.10.10", DestIp: "192.168.1.101,192.168.201.0/24,192.168.10.30-192.168.10.40",
			State:     "enable",
			IsDefault: false, RuleNumber: 1110,
			AllowStates: "new,established,invalid,related",
			Protocol:    "all", Action: "accept"}

		ruleInfo2 := ruleInfo{
			SourceIp: "192.168.2.100", DestIp: "192.168.2.101",
			DestPort: "1000-1007", SourcePort: "10000-10010",
			State:     "enable",
			IsDefault: false, RuleNumber: 1002,
			AllowStates: "established,related",
			Tcp:         "SYN,ACK",
			Protocol:    "tcp", Action: "drop"}

		ruleInfo3 := ruleInfo{
			SourceIp: "192.168.3.100,192.168.3.101, 192.168.3.102", DestIp: "192.168.103.100,192.168.103.101, 192.168.103.102",
			DestPort: "1000,1002,1004,100-200", SourcePort: "1000,1002,1004,100-200",
			State:     "enable",
			IsDefault: false, RuleNumber: 1003,
			Protocol: "udp", Action: "reject"}

		ruleInfo4 := ruleInfo{
			SourceIp: "192.168.104.0/24", DestIp: "192.168.204.0/24",
			State:     "enable",
			IsDefault: false, RuleNumber: 1010,
			AllowStates: "new,related",
			Protocol:    "icmp", Action: "accept"}

		ruleInfo5 := ruleInfo{
			SourceIp: "30.1.1.1-30.1.1.10", DestIp: "40.1.1.1-40.1.1.10",
			DestPort: "120-220,320,420-520", SourcePort: "130-230,330,430-530",
			State:     "enable",
			IsDefault: false, RuleNumber: 1122,
			Protocol: "tcp", Action: "drop",
		}

		ruleInfo6 := ruleInfo{
			SourceIp: "30.1.1.1-30.1.1.11", DestIp: "40.1.1.1-40.1.1.11",
			DestPort: "120-220", SourcePort: "130-230",
			State:     "disable",
			IsDefault: false, RuleNumber: 1123,
			Protocol: "tcp", Action: "drop",
		}

		rulesApply := []ruleInfo{ruleInfo1, ruleInfo2, ruleInfo3, ruleInfo4, ruleInfo5, ruleInfo6}
		rules := []ruleInfo{ruleInfo1, ruleInfo2, ruleInfo3, ruleInfo4, ruleInfo5}

		ruleSetName1 := buildRuleSetName(utils.PrivateNicsForUT[0].Name, FIREWALL_DIRECTION_IN)
		ruleSetName2 := buildRuleSetName(utils.PubNicForUT.Name, FIREWALL_DIRECTION_OUT)

		By("####test applyUserRules re-install rules #######")
		ruleSetInfo1 := ruleSetInfo{
			Name:             "rs1",
			ActionType:       "accept",
			EnableDefaultLog: false,
			Rules:            rulesApply}

		ruleSetInfo2 := ruleSetInfo{
			Name:             "rs2",
			ActionType:       "reject",
			EnableDefaultLog: false,
			Rules:            rulesApply,
		}

		ethRuleSetRef3 := ethRuleSetRef{
			Mac:         utils.PrivateNicsForUT[0].Mac,
			Forward:     FIREWALL_DIRECTION_IN,
			RuleSetInfo: ruleSetInfo1,
		}
		ethRuleSetRef4 := ethRuleSetRef{
			Mac:         utils.PubNicForUT.Mac,
			Forward:     FIREWALL_DIRECTION_OUT,
			RuleSetInfo: ruleSetInfo2,
		}
		refs2 := []ethRuleSetRef{ethRuleSetRef3, ethRuleSetRef4}
		acmd := applyUserRuleCmd{Refs: refs2}
		err := applyUserRules(&acmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("applyUserRules re-install rules: %+v", err))
		// check iptables default rule
		checkDefaultAction(ruleSetName1, "accept")
		checkDefaultAction(ruleSetName2, "reject")
		// check iptables rules
		checkIptableRule(ruleSetName1, rules, false)
		checkIptableRule(ruleSetName2, rules, false)

		By("####test applyUserRules re-install rules 2 #######")
		err = applyUserRules(&acmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("applyUserRules re-install rules: %+v", err))
		checkIptableRule(ruleSetName1, rules, false)
		checkIptableRule(ruleSetName2, rules, false)

		/* applyUserRules command will remove all rule, and add new rules */
		By("####test applyUserRules re-install rules 3 #######")
		ruleSetInfo1 = ruleSetInfo{
			Name:             "rs1",
			ActionType:       "accept",
			EnableDefaultLog: false,
			Rules:            nil}

		ruleSetInfo2 = ruleSetInfo{
			Name:             "rs2",
			ActionType:       "reject",
			EnableDefaultLog: false,
			Rules:            nil,
		}

		ethRuleSetRef3 = ethRuleSetRef{
			Mac:         utils.PrivateNicsForUT[0].Mac,
			Forward:     FIREWALL_DIRECTION_IN,
			RuleSetInfo: ruleSetInfo1,
		}
		ethRuleSetRef4 = ethRuleSetRef{
			Mac:         utils.PubNicForUT.Mac,
			Forward:     FIREWALL_DIRECTION_OUT,
			RuleSetInfo: ruleSetInfo2,
		}
		refs2 = []ethRuleSetRef{ethRuleSetRef3, ethRuleSetRef4}
		acmd = applyUserRuleCmd{Refs: refs2}
		log.Debugf("start apply user rule")
		err = applyUserRules(&acmd)
		log.Debugf("apply user rule error is %v", err)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("applyUserRules re-install rules: %+v", err))
		// check iptables default rule
		checkDefaultAction(ruleSetName1, "accept")
		checkDefaultAction(ruleSetName2, "reject")

		checkIptableRule(ruleSetName1, rules, true)
		checkIptableRule(ruleSetName2, rules, true)
	})

	/* when attach a vpc nic to firewall or add new rules to firewall  */
	It("[IPTABLES]FIREWALL : test rules add/remove", func() {
		ruleInfo1 := ruleInfo{
			SourceIp: "192.168.1.100,192.168.101.0/24,192.168.100.1-192.168.100.10", DestIp: "192.168.1.101,192.168.201.0/24,192.168.100.11-192.168.100.20",
			DestPort: "1000", SourcePort: "10000",
			State:     "enable",
			IsDefault: false, RuleNumber: 2110,
			AllowStates: "new,established,invalid,related",
			Protocol:    "tcp", Action: "accept"}

		ruleInfo2 := ruleInfo{
			SourceIp: "10.10.10.10-10.10.10.100", DestIp: "10.20.20.20-10.20.20.200",
			DestPort: "140-240,340,440-540", SourcePort: "140-240,340,440-540",
			State:     "enable",
			IsDefault: false, RuleNumber: 1122,
			Protocol: "udp", Action: "accept",
		}

		ruleInfo3 := ruleInfo{
			SourceIp: "10.10.10.10-10.10.10.100", DestIp: "10.20.20.20-10.20.20.200",
			DestPort: "140-240,340,440-540", SourcePort: "140-240,340,440-540",
			State:     "disable",
			IsDefault: false, RuleNumber: 1123,
			Protocol: "tcp", Action: "accept",
		}

		rulesCreate := []ruleInfo{ruleInfo1, ruleInfo2, ruleInfo3}
		rules := []ruleInfo{ruleInfo1, ruleInfo2}
		ruleSet := ruleSetInfo{
			Name:             "rs1",
			ActionType:       "accept",
			EnableDefaultLog: false,
			Rules:            rulesCreate}

		ethRuleSetRef1 := ethRuleSetRef{
			Mac:         utils.PrivateNicsForUT[0].Mac,
			Forward:     FIREWALL_DIRECTION_IN,
			RuleSetInfo: ruleSet,
		}

		ethRuleSetRef2 := ethRuleSetRef{
			Mac:         utils.PrivateNicsForUT[0].Mac,
			Forward:     FIREWALL_DIRECTION_OUT,
			RuleSetInfo: ruleSet,
		}

		ruleSetName1 := buildRuleSetName(utils.PrivateNicsForUT[0].Name, FIREWALL_DIRECTION_IN)
		ruleSetName2 := buildRuleSetName(utils.PrivateNicsForUT[0].Name, FIREWALL_DIRECTION_OUT)

		By("####test add rule to firewall #######")
		createRuleCmd2 := &createRuleCmd{Ref: ethRuleSetRef1}
		err := createRule(createRuleCmd2)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("createRuleByIptables add rules failed: %+v", err))
		createRuleCmd3 := &createRuleCmd{Ref: ethRuleSetRef2}
		err3 := createRule(createRuleCmd3)
		gomega.Expect(err3).To(gomega.BeNil(), fmt.Sprintf("createRuleByIptables add rules failed: %+v", err))
		checkDefaultAction(ruleSetName1, "accept")
		checkCreateRuleByIptables(utils.PrivateNicsForUT[0].Name, ruleSetName1, ethRuleSetRef1)
		checkCreateRuleByIptables(utils.PrivateNicsForUT[0].Name, ruleSetName2, ethRuleSetRef2)
		checkIptableRule(ruleSetName1, rules, false)

		By("####test change rule state to disable #######")
		cCmd1 := changeRuleStateCmd{Rule: ruleInfo1, State: "disable", Mac: utils.PrivateNicsForUT[0].Mac, Forward: FIREWALL_DIRECTION_IN}
		cCmd2 := changeRuleStateCmd{Rule: ruleInfo2, State: "disable", Mac: utils.PrivateNicsForUT[0].Mac, Forward: FIREWALL_DIRECTION_IN}
		changeRuleState(&cCmd1)
		changeRuleState(&cCmd2)
		checkIptableRule(ruleSetName1, rules, true)

		By("####test change rule state to enable #######")
		cCmd1.State = "enable"
		cCmd2.State = "enable"
		changeRuleState(&cCmd1)
		changeRuleState(&cCmd2)
		checkIptableRule(ruleSetName1, rules, false)

		By("####test deleteRule #######")
		deleteRuleCmd1 := deleteRuleCmd{Ref: ethRuleSetRef1}
		deleteRule(&deleteRuleCmd1)
		checkIptableRule(ruleSetName1, rules, true)
		deleteRuleCmd2 := deleteRuleCmd{Ref: ethRuleSetRef2}
		deleteRule(&deleteRuleCmd2)
		checkIptableRule(ruleSetName2, rules, true)
	})

	It("[IPTABLES]FIREWALL : test update firewall", func() {
		ruleInfo1 := ruleInfo{
			SourceIp: "10.2.2.1-10.2.2.10", DestIp: "20.2.2.1-20.2.2.10",
			DestPort: "100-200,300,400-500", SourcePort: "150-250,350,450-550",
			State:     "enable",
			IsDefault: false, RuleNumber: 1234,
			Protocol: "udp", Action: "accept",
		}

		ruleInfo2 := ruleInfo{
			SourceIp: "10.2.2.1-10.2.2.10,172.16.90.157,192.168.100.0/24", DestIp: "20.2.2.1-20.2.2.10,172.16.90.100,192.168.10.0/24",
			DestPort: "100-200,300", SourcePort: "150-250",
			State:     "enable",
			IsDefault: false, RuleNumber: 1234,
			Protocol: "udp", Action: "accept",
		}

		ruleInfo3 := ruleInfo{
			SourceIp: "10.2.2.1-10.2.2.10", DestIp: "20.2.2.1-20.2.2.10",
			DestPort: "100-200,300,400-500", SourcePort: "150-250,350,450-550",
			State:     "enable",
			IsDefault: false, RuleNumber: 1235,
			Protocol: "udp", Action: "accept",
		}

		ruleSet := ruleSetInfo{
			Name:             "rs10",
			ActionType:       "accept",
			EnableDefaultLog: false,
		}
		ethRuleSetRef := ethRuleSetRef{
			Mac:         utils.PrivateNicsForUT[0].Mac,
			Forward:     FIREWALL_DIRECTION_IN,
			RuleSetInfo: ruleSet,
		}
		ruleSetName1 := buildRuleSetName(utils.PrivateNicsForUT[0].Name, FIREWALL_DIRECTION_IN)
		cmd := &createRuleCmd{Ref: ethRuleSetRef}

		log.Debugf("####test add oldRule start #######")
		cmd.Ref.RuleSetInfo.Rules = []ruleInfo{ruleInfo1, ruleInfo3}
		err := createRule(cmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("createRuleByIptables add rules failed: %+v", err))
		checkCreateRuleByIptables(utils.PrivateNicsForUT[0].Name, ruleSetName1, cmd.Ref)
		checkIptableRule(ruleSetName1, []ruleInfo{ruleInfo1, ruleInfo3}, false)

		log.Debugf("####test add newRule, oldRule should be deleted #######")
		cmd.Ref.RuleSetInfo.Rules = []ruleInfo{ruleInfo2, ruleInfo3}
		err = createRule(cmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("createRuleByIptables add rules failed: %+v", err))
		checkCreateRuleByIptables(utils.PrivateNicsForUT[0].Name, ruleSetName1, cmd.Ref)
		checkIptableRule(ruleSetName1, []ruleInfo{ruleInfo2, ruleInfo3}, false)

		log.Debugf("####test delete newRule start####")
		ethRuleSetRef.RuleSetInfo.Rules = []ruleInfo{ruleInfo2, ruleInfo3}
		deleteRuleCmd := &deleteRuleCmd{Ref: ethRuleSetRef}
		deleteRule(deleteRuleCmd)
		checkIptableRule(ruleSetName1, []ruleInfo{ruleInfo2}, true)
		checkIptableRule(ruleSetName1, []ruleInfo{ruleInfo3}, true)
	})

	/* change firewall default action  */
	It("[IPTABLES]FIREWALL : test change default action", func() {
		ruleSetName := buildRuleSetName(utils.PrivateNicsForUT[0].Name, "IN")
		updateRuleSetCmd1 := updateRuleSetCmd{Mac: utils.PrivateNicsForUT[0].Mac, Forward: "IN", ActionType: "reject"}
		updateRuleSet(&updateRuleSetCmd1)
		checkDefaultAction(ruleSetName, "reject")

		updateRuleSetCmd1 = updateRuleSetCmd{Mac: utils.PrivateNicsForUT[0].Mac, Forward: "IN", ActionType: "drop"}
		updateRuleSet(&updateRuleSetCmd1)
		checkDefaultAction(ruleSetName, "drop")

		updateRuleSetCmd1 = updateRuleSetCmd{Mac: utils.PrivateNicsForUT[0].Mac, Forward: "IN", ActionType: "accept"}
		updateRuleSet(&updateRuleSetCmd1)
		checkDefaultAction(ruleSetName, "accept")
	})

	/* delete firewall  */
	It("[IPTABLES]FIREWALL : test delete firewall", func() {

		//ethInfo+table -> ref getFirewallConfig(getConfigCmd1)
		nicTypeInfo1 := nicTypeInfo{Mac: utils.PubNicForUT.Mac, NicType: "Public"}
		nicTypeInfo2 := nicTypeInfo{Mac: utils.PrivateNicsForUT[0].Mac, NicType: "Private"}
		nicTypeInfo := []nicTypeInfo{nicTypeInfo1, nicTypeInfo2}

		//delete firewall config
		By("TestCreateUserRule deleteUserRule ")
		getConfigCmd1 := getConfigCmd{nicTypeInfo}
		deleteUserRule(&getConfigCmd1)
		checkDeleteUserRuleByIpTables()
	})

	It("[IPTABLES]FIREWALL : test modify firewall rule and change state", func() {
		ruleInfo1 := ruleInfo{
			SourceIp: "10.10.10.1,10.10.10.10-10.10.10.20", DestIp: "20.20.20.1,20.20.20.10-20.20.20.20",
			State:     "enable",
			IsDefault: false, RuleNumber: 1234,
			Protocol: "udp", Action: "accept",
		}

		ruleSet := ruleSetInfo{
			Name:             "rs10",
			ActionType:       "accept",
			EnableDefaultLog: false,
		}
		ethRuleSetRef := ethRuleSetRef{
			Mac:         utils.PrivateNicsForUT[0].Mac,
			Forward:     FIREWALL_DIRECTION_IN,
			RuleSetInfo: ruleSet,
		}
		ruleSetName1 := buildRuleSetName(utils.PrivateNicsForUT[0].Name, FIREWALL_DIRECTION_IN)
		cmd := &createRuleCmd{Ref: ethRuleSetRef}

		cmd.Ref.RuleSetInfo.Rules = []ruleInfo{ruleInfo1}
		err := createRule(cmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("createRuleByIptables add rules failed: %+v", err))
		checkCreateRuleByIptables(utils.PrivateNicsForUT[0].Name, ruleSetName1, cmd.Ref)
		checkIptableRule(ruleSetName1, []ruleInfo{ruleInfo1}, false)

		ruleInfo1.State = "disable"
		cmd.Ref.RuleSetInfo.Rules = []ruleInfo{ruleInfo1}
		err = createRule(cmd)
		gomega.Expect(err).To(gomega.BeNil(), fmt.Sprintf("createRuleByIptables add rules failed: %+v", err))
		checkIptableRule(ruleSetName1, []ruleInfo{ruleInfo1}, true)
	})

	It("[IPTABLES]FIREWALL : firewall_iptables destroying env", func() {
		var nicCmd configureNicCmd
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PrivateNicsForUT[0])
		removeNic(&nicCmd)
		for i, _ := range nicCmd.Nics {
			checkNicFirewallDeleteByIpTables(nicCmd.Nics[i])
		}
		utils.SetSkipVyosIptablesForUT(false)
	})

})

func checkIptableRuleByRuleNum(ruleSetName string, rules []ruleInfo, delete bool) {
	table := utils.NewIpTables(utils.FirewallTable)

	for _, r := range rules {
		rule := getIpTableRuleFromRule(ruleSetName, r)
		res := false

		for _, tr := range table.Rules {
			if rule.GetChainName() != tr.GetChainName() {
				continue
			}
			if rule.GetRuleNumber() == tr.GetRuleNumber() {
				res = true
				break
			}
		}

		if delete {
			gomega.Expect(res).To(gomega.BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
		} else {
			gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
		}
	}
}

//check ruleinfo -> iptablerule
func checkIptableRule(ruleSetName string, rules []ruleInfo, delete bool) {
	table := utils.NewIpTables(utils.FirewallTable)

	for _, r := range rules {
		rule := getIpTableRuleFromRule(ruleSetName, r)
		res := table.Check(rule)
		if delete {
			gomega.Expect(res).To(gomega.BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
		} else {
			gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
		}

		if r.EnableLog {
			rule1 := *rule
			rule1.SetAction(utils.IPTABLES_ACTION_LOG)
			res := table.Check(rule)
			if delete {
				gomega.Expect(res).To(gomega.BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
			} else {
				gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
			}
		}
	}
}

func checkApplyUserRuleByIpTables(cmd *applyUserRuleCmd) {
	table := utils.NewIpTables(utils.FirewallTable)

	for _, ref := range cmd.Refs {
		nicName, err := utils.GetNicNameByMac(ref.Mac)
		utils.PanicOnError(err)
		ruleSetName := buildRuleSetName(nicName, ref.Forward)

		//create ruleSet and add last rule
		table.AddChain(ruleSetName)
		rule := utils.NewDefaultIpTableRule(ruleSetName, utils.IPTABLES_RULENUMBER_MAX)
		rule.SetAction(ref.RuleSetInfo.ActionType)
		res := table.Check(rule)
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

		/* check chain */
		if ref.Forward == FIREWALL_DIRECTION_OUT {
			rule := utils.NewIpTableRule(utils.VYOS_FWD_OUT_ROOT_CHAIN)
			rule.SetAction(ruleSetName)
			rule.SetOutNic(nicName)
			res := table.Check(rule)
			gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
		} else if ref.Forward == FIREWALL_DIRECTION_IN {
			rule := utils.NewIpTableRule(utils.VYOS_FWD_ROOT_CHAIN)
			rule.SetAction(ruleSetName)
			rule.SetOutNic(nicName)
			res := table.Check(rule)
			gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
		}

		/* check rule */
		for _, r := range ref.RuleSetInfo.Rules {
			rule := getIpTableRuleFromRule(ruleSetName, r)
			res = table.Check(rule)
			gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

			if r.EnableLog {
				rule1 := rule.Copy()
				rule1.SetAction(utils.IPTABLES_ACTION_LOG)
				res = table.Check(rule1)
				gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule1.String()))
			}
		}
	}

}

func checkCreateRuleByIptables(nicName, ruleSetName string, ref ethRuleSetRef) {

	table := utils.NewIpTables(utils.FirewallTable)

	if ref.Forward == FIREWALL_DIRECTION_OUT {
		rule := utils.NewIpTableRule(utils.VYOS_FWD_OUT_ROOT_CHAIN)
		rule.SetAction(ruleSetName)
		rule.SetOutNic(nicName)
		res := table.Check(rule)
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
	} else if ref.Forward == FIREWALL_DIRECTION_IN {
		rule := utils.NewIpTableRule(utils.VYOS_FWD_ROOT_CHAIN)
		rule.SetAction(ruleSetName)
		rule.SetInNic(nicName)
		res := table.Check(rule)
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
	}

	if ref.Forward == FIREWALL_DIRECTION_OUT {
		rule := utils.NewDefaultIpTableRule(ruleSetName, utils.IPTABLES_RULENUMBER_MAX)
		rule.SetAction(utils.IPTABLES_ACTION_RETURN)
		res := table.Check(rule)
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
	}

	rule := utils.NewDefaultIpTableRule(ruleSetName, utils.IPTABLES_RULENUMBER_MAX)
	rule.SetAction(getIptablesRuleActionFromRuleAction(ref.RuleSetInfo.ActionType))
	res := table.Check(rule)
	gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))

}

func checkDeleteUserRuleByIpTables() {
	table := utils.NewIpTables(utils.FirewallTable)

	inChainNames := utils.GetFirewallInputChains(table)
	for _, name := range inChainNames {
		rule := utils.NewDefaultIpTableRule(name, utils.IPTABLES_RULENUMBER_9999)
		rule.SetAction(utils.IPTABLES_ACTION_RETURN)
		res := table.Check(rule)
		gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
	}

	outChainNames := utils.GetFirewallOutputChains(table)
	for _, name := range outChainNames {
		rule := utils.NewDefaultIpTableRule(name, utils.IPTABLES_RULENUMBER_MAX)
		res := table.Check(rule)
		gomega.Expect(res).To(gomega.BeFalse(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
	}
}

func checkDefaultAction(ruleSetName, action string) {
	table := utils.NewIpTables(utils.FirewallTable)
	rule := utils.NewDefaultIpTableRule(ruleSetName, utils.IPTABLES_RULENUMBER_MAX)
	rule.SetAction(getIptablesRuleActionFromRuleAction(action))
	res := table.Check(rule)
	gomega.Expect(res).To(gomega.BeTrue(), fmt.Sprintf("firewall rule [%s] check failed", rule.String()))
}

func checkDefaultNicRules(nicInfo nicTypeInfo, refs []ethRuleSetRef) {
	gomega.Expect(len(refs) == 3).To(gomega.BeTrue(), fmt.Sprintf("nic has %d rulesets", len(refs)))
	for _, ref := range refs {
		gomega.Expect(ref.Mac == nicInfo.Mac).To(gomega.BeTrue(),
			fmt.Sprintf("ref mac address: %s different from nic mac:%s", ref.Mac, nicInfo.Mac))

		if ref.Forward == "out" {
			gomega.Expect(len(ref.RuleSetInfo.Rules) == 0).To(gomega.BeTrue(),
				fmt.Sprintf("there are %d rule in out direction", len(ref.RuleSetInfo.Rules)))
			gomega.Expect(ref.RuleSetInfo.ActionType == "accept").To(gomega.BeTrue(),
				fmt.Sprintf("default action type:%s ", ref.RuleSetInfo.ActionType))
			gomega.Expect(ref.RuleSetInfo.EnableDefaultLog).To(gomega.BeFalse(),
				fmt.Sprintf("enable log %v", ref.RuleSetInfo.EnableDefaultLog))
		} else if ref.Forward == "local" {
			gomega.Expect(len(ref.RuleSetInfo.Rules) == 3).To(gomega.BeTrue(),
				fmt.Sprintf("there are %d rule in local direction", len(ref.RuleSetInfo.Rules)))
			gomega.Expect(ref.RuleSetInfo.ActionType == "reject").To(gomega.BeTrue(),
				fmt.Sprintf("default action type:%s ", ref.RuleSetInfo.ActionType))
			gomega.Expect(ref.RuleSetInfo.EnableDefaultLog).To(gomega.BeFalse(),
				fmt.Sprintf("enable log %v", ref.RuleSetInfo.EnableDefaultLog))

			nicName, _ := utils.GetNicNameByMac(nicInfo.Mac)
			ip, _ := utils.GetIpByNicName(nicName)
			r1 := ref.RuleSetInfo.Rules[0]
			gomega.Expect(r1.RuleNumber == 1).To(gomega.BeTrue(),
				fmt.Sprintf("local direction 1st rulenumber [%+v]", r1))
			gomega.Expect(r1.AllowStates == "related,established").To(gomega.BeTrue(),
				fmt.Sprintf("local direction 1st allowstate %s", r1.AllowStates))
			gomega.Expect(r1.Action == strings.ToLower(utils.IPTABLES_ACTION_ACCEPT)).To(gomega.BeTrue(),
				fmt.Sprintf("in direction 1st action [%+v]", r1.Action))

			r2 := ref.RuleSetInfo.Rules[1]
			gomega.Expect(r2.RuleNumber == 2).To(gomega.BeTrue(),
				fmt.Sprintf("in direction 2nd rulenumber %d", r2.RuleNumber))
			gomega.Expect(r2.AllowStates == "").To(gomega.BeTrue(),
				fmt.Sprintf("in direction 2nd allowstate %s", r2.AllowStates))
			gomega.Expect(r2.Action == strings.ToLower(utils.IPTABLES_ACTION_ACCEPT)).To(gomega.BeTrue(),
				fmt.Sprintf("in direction 2nd action [%+v]", r2.Action))
			gomega.Expect(r2.Protocol == "ICMP").To(gomega.BeTrue(),
				fmt.Sprintf("in direction 2nd Protocol [%+v]", r2.Protocol))
			gomega.Expect(r2.DestIp == ip).To(gomega.BeTrue(),
				fmt.Sprintf("in direction 2nd DestIp [%+v]", r2.DestIp))

			r3 := ref.RuleSetInfo.Rules[2]
			gomega.Expect(r3.RuleNumber == 3).To(gomega.BeTrue(),
				fmt.Sprintf("in direction 3rd rulenumber %d", r3.RuleNumber))
			gomega.Expect(r3.AllowStates == "").To(gomega.BeTrue(),
				fmt.Sprintf("in direction 3rd allowstate %s", r3.AllowStates))
			gomega.Expect(r3.Action == strings.ToLower(utils.IPTABLES_ACTION_REJECT)).To(gomega.BeTrue(),
				fmt.Sprintf("in direction 3rd action [%+v]", r3.Action))
			gomega.Expect(r3.DestPort == "22").To(gomega.BeTrue(),
				fmt.Sprintf("in direction 3rd dport [%+v]", r3.DestPort))
			gomega.Expect(r3.Protocol == "TCP").To(gomega.BeTrue(),
				fmt.Sprintf("in direction 3rd Protocol [%+v]", r3.Protocol))
			gomega.Expect(r3.DestIp == ip).To(gomega.BeTrue(),
				fmt.Sprintf("in direction 3rd DestIp [%+v]", r3.DestIp))
		} else {
			gomega.Expect(len(ref.RuleSetInfo.Rules) > 2).To(gomega.BeTrue(),
				fmt.Sprintf("there are %d rule in in direction", len(ref.RuleSetInfo.Rules)))
			gomega.Expect(ref.RuleSetInfo.ActionType == "reject").To(gomega.BeTrue(),
				fmt.Sprintf("default action type:%s ", ref.RuleSetInfo.ActionType))
			gomega.Expect(ref.RuleSetInfo.EnableDefaultLog).To(gomega.BeFalse(),
				fmt.Sprintf("enable log %v", ref.RuleSetInfo.EnableDefaultLog))
			r1 := ref.RuleSetInfo.Rules[0]
			gomega.Expect(r1.RuleNumber == utils.FORWARD_CHAIN_SYSTEM_RULE_RULE_NUMBER_MIN).To(gomega.BeTrue(),
				fmt.Sprintf("in direction 1st rulenumber [%+v]", r1))
			gomega.Expect(r1.AllowStates == "related,established").To(gomega.BeTrue(),
				fmt.Sprintf("in direction 1st allowstate %s", r1.AllowStates))
			gomega.Expect(r1.Action == strings.ToLower(utils.IPTABLES_ACTION_ACCEPT)).To(gomega.BeTrue(),
				fmt.Sprintf("in direction 1st action [%+v]", r1.Action))

			r2 := ref.RuleSetInfo.Rules[len(ref.RuleSetInfo.Rules)-1]
			gomega.Expect(r2.RuleNumber == utils.IPTABLES_RULENUMBER_9999).To(gomega.BeTrue(),
				fmt.Sprintf("in direction 2nd rulenumber %d", r2.RuleNumber))
			gomega.Expect(r2.AllowStates == "new").To(gomega.BeTrue(),
				fmt.Sprintf("in direction 2nd allowstate %s", r2.AllowStates))
			gomega.Expect(r2.Action == strings.ToLower(utils.IPTABLES_ACTION_ACCEPT)).To(gomega.BeTrue(),
				fmt.Sprintf("in direction 2nd action [%+v]", r1.Action))
		}
	}
}

func checkEipRulesInChain(isPubNic bool, nicInfo nicTypeInfo, refs []ethRuleSetRef) {
	for _, ref := range refs {
		if ref.Forward == "in" {
			r1 := ref.RuleSetInfo.Rules[1]
			gomega.Expect(r1.RuleNumber == 5001).To(gomega.BeTrue(),
				fmt.Sprintf("in direction eip rule rulenumber [%+v]", r1))
			gomega.Expect(r1.SourcePort == "").To(gomega.BeTrue(),
				fmt.Sprintf("in direction eip SourcePort [%+v]", r1.SourcePort))
			gomega.Expect(r1.DestPort == "").To(gomega.BeTrue(),
				fmt.Sprintf("in direction eip DestPort [%+v]", r1.DestPort))
			if isPubNic {
				gomega.Expect(r1.DestIp == "eip-group").To(gomega.BeTrue(),
					fmt.Sprintf("in direction eip DestIp [%+v]", r1.DestIp))
			} else {
				gomega.Expect(r1.SourceIp == "eip-group").To(gomega.BeTrue(),
					fmt.Sprintf("in direction eip SourceIp [%+v]", r1.SourceIp))
			}
		}
	}
}
