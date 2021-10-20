package plugin

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
	"strconv"
)

const (
	SET_SNAT_PATH       = "/setsnat"
	REMOVE_SNAT_PATH    = "/removesnat"
	SYNC_SNAT_PATH      = "/syncsnat"
	SET_SNAT_STATE_PATH = "/setsnatservicestate"
)

type snatInfo struct {
	PublicNicMac  string `json:"publicNicMac"`
	PublicIp      string `json:"publicIp"`
	PrivateNicMac string `json:"privateNicMac"`
	PrivateNicIp  string `json:"privateNicIp"`
	SnatNetmask   string `json:"snatNetmask"`
	State 		  bool   `json:"state"`
}

type setSnatCmd struct {
	Snat snatInfo `json:"snat"`
}

type removeSnatCmd struct {
	NatInfo []snatInfo `json:"natInfo"`
}

type syncSnatCmd struct {
	Snats  []snatInfo `json:"snats"`
	Enable bool       `json:"enable"`
}

type setSnatStateCmd struct {
	Snats  []snatInfo `json:"snats"`
	Enable bool       `json:"enabled"`
}

type setNetworkServiceRsp struct {
	ServiceStatus string `json:"serviceStatus"`
}

var SNAT_RULE_NUMBER = 9999

func getNicSNATRuleNumberByConfig(tree *server.VyosConfigTree, snat snatInfo) (pubNicRuleNo int, priNicRuleNo int) {
	rules := tree.Get("nat source rule")
	ruleId1 := ""
	ruleId2 := ""
	if rules != nil {
		for _, r := range rules.Children() {
			outNic, err := utils.GetNicNameByMac(snat.PublicNicMac)
			utils.PanicOnError(err)
			address, err := utils.GetNetworkNumber(snat.PrivateNicIp, snat.SnatNetmask)
			utils.PanicOnError(err)
			sAddr := r.Get("source address")
			tAddr := r.Get("translation address")
			outIf := r.Get("outbound-interface")
			if  sAddr != nil && sAddr.Value() == address &&
				tAddr != nil && tAddr.Value() == snat.PublicIp &&
				outIf != nil && outIf.Value() == outNic {
				ruleId1 = r.Name()
				break
			}
		}
		for _, r := range rules.Children() {
			inNic, err := utils.GetNicNameByMac(snat.PrivateNicMac)
			utils.PanicOnError(err)
			address, err := utils.GetNetworkNumber(snat.PrivateNicIp, snat.SnatNetmask)
			utils.PanicOnError(err)
			sAddr := r.Get("source address")
			tAddr := r.Get("translation address")
			outIf := r.Get("outbound-interface")
			if  sAddr != nil && sAddr.Value() == address &&
				tAddr != nil && tAddr.Value() == snat.PublicIp &&
				outIf != nil && outIf.Value() == inNic {
				ruleId2 = r.Name()
				break
			}
		}
	}
	ruleId3, _ := strconv.Atoi(ruleId1)
	ruleId4, _ := strconv.Atoi(ruleId2)
	return ruleId3, ruleId4
}

func getNicSNATRuleNumber(nicNo int) (pubNicRuleNo int, priNicRuleNo int) {
	pubNicRuleNo = SNAT_RULE_NUMBER - nicNo*2
	priNicRuleNo = pubNicRuleNo - 1
	return
}

//Deprecated
func setSnatRule(pubNic, priNic, priCidr, pubIp string) {
	rule := utils.NewSnatIptablesRule(false, true, priCidr, "224.0.0.0/8", pubNic, utils.SNAT, utils.SNATComment+priCidr, pubIp, 0)
	utils.InsertNatRule(rule, utils.POSTROUTING)
	rule = utils.NewSnatIptablesRule(false, true, priCidr, "224.0.0.0/8", priNic, utils.SNAT, utils.SNATComment+priCidr, pubIp, 0)
	utils.InsertNatRule(rule, utils.POSTROUTING)
}

//Deprecated
func setSnatHandler(ctx *server.CommandContext) interface{}  {
	cmd := &setSnatCmd{}
	ctx.GetCommand(cmd)
	
	return setSnat(cmd)
}

//Deprecated
func setSnat(cmd *setSnatCmd) interface{} {
	s := cmd.Snat
	outNic, err := utils.GetNicNameByMac(s.PublicNicMac)
	utils.PanicOnError(err)
	inNic, err := utils.GetNicNameByMac(s.PrivateNicMac)
	utils.PanicOnError(err)
	nicNumber, err := utils.GetNicNumber(inNic)
	utils.PanicOnError(err)
	address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
	utils.PanicOnError(err)

	if utils.IsSkipVyosIptables() {
		setSnatRule(outNic, inNic, address, s.PublicIp)
	} else {
		// make source nat rule as the latest rule
		// in case there are EIP rules
		tree := server.NewParserFromShowConfiguration().Tree
		pubNicRuleNo, priNicRuleNo := getNicSNATRuleNumber(nicNumber)
		setted := false
		if !hasRuleNumberForAddress(tree, address, pubNicRuleNo) {
			tree.SetSnatWithRuleNumber(pubNicRuleNo,
				fmt.Sprintf("outbound-interface %s", outNic),
				fmt.Sprintf("source address %v", address),
				"destination address !224.0.0.0/8",
				fmt.Sprintf("translation address %s", s.PublicIp),
			)
			setted = true
		}

		if !hasRuleNumberForAddress(tree, address, priNicRuleNo) {
			tree.SetSnatWithRuleNumber(priNicRuleNo,
				fmt.Sprintf("outbound-interface %s", inNic),
				fmt.Sprintf("source address %v", address),
				"destination address !224.0.0.0/8",
				fmt.Sprintf("translation address %s", s.PublicIp),
			)
			setted = true
		}

		if setted {
			tree.Apply(false)
		}
	}

	return nil
}

func deleteSnatRule(priCidr string) {
	utils.DeleteSNatRuleByComment(utils.SNATComment + priCidr)
}

func removeSnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &removeSnatCmd{}
	ctx.GetCommand(&cmd)
	
	return removeSnat(cmd)
}

func removeSnat(cmd *removeSnatCmd) interface{} {
	if utils.IsSkipVyosIptables() {
		for _, s := range cmd.NatInfo {
			address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
			utils.PanicOnError(err)
			deleteSnatRule(address)
		}
	} else {
		tree := server.NewParserFromShowConfiguration().Tree

		for _, s := range cmd.NatInfo {
			pubNicRuleNo, priNicRuleNo := getNicSNATRuleNumberByConfig(tree, s)
			if rs := tree.Get(fmt.Sprintf("nat source rule %v", pubNicRuleNo)); rs == nil {
				log.Debugf(fmt.Sprintf("nat source rule %v not found", pubNicRuleNo))
			} else {
				rs.Delete()
			}

			if rs := tree.Get(fmt.Sprintf("nat source rule %v", priNicRuleNo)); rs == nil {
				log.Debugf(fmt.Sprintf("nat source rule %v not found", priNicRuleNo))
			} else {
				rs.Delete()
			}
		}
		tree.Apply(false)
	}

	return nil
}

func hasRuleNumberForAddress(tree *server.VyosConfigTree, address string, ruleNo int) bool {
	rs := tree.Get(fmt.Sprintf("nat source rule %v", ruleNo))
	if rs == nil {
		return false
	}

	return true
}

func syncSnatByIptables(Snats []snatInfo, state bool) {
	/* delete all snat rules */
	utils.DeleteSNatRuleByComment(utils.SNATComment)

	if state == false {
		return
	}

	for _, s := range Snats {
		outNic, err := utils.GetNicNameByMac(s.PublicNicMac)
		utils.PanicOnError(err)
		inNic, err := utils.GetNicNameByMac(s.PrivateNicMac)
		utils.PanicOnError(err)
		address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
		utils.PanicOnError(err)

		setSnatRule(outNic, inNic, address, s.PublicIp)
	}
}

func applySnatRules(Snats []snatInfo, state bool) bool {
	tree := server.NewParserFromShowConfiguration().Tree

	update := false
	for _, s := range Snats {
		outNic, err := utils.GetNicNameByMac(s.PublicNicMac)
		utils.PanicOnError(err)
		inNic, err := utils.GetNicNameByMac(s.PrivateNicMac)
		utils.PanicOnError(err)
		nicNumber, err := utils.GetNicNumber(inNic)
		utils.PanicOnError(err)
		address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
		utils.PanicOnError(err)

		pubNicRuleNo, priNicRuleNo := getNicSNATRuleNumberByConfig(tree, s)
		if s.State == true {
			newPubNicRuleNo, newPriNicRuleNo := getNicSNATRuleNumber(nicNumber)

			for j := 1; ; j++ {
				if tree.Getf("nat source rule %v", newPubNicRuleNo) == nil && tree.Getf("nat source rule %v", newPriNicRuleNo) == nil {
					break
				} else {
					newPubNicRuleNo, newPriNicRuleNo = getNicSNATRuleNumber(nicNumber+j)
				}
			}

			if pubNicRuleNo == 0 {
				pubNicRuleNo = newPubNicRuleNo
				pubRs := tree.Getf("nat source rule %v", pubNicRuleNo)
				if pubRs == nil {
					tree.SetSnatWithRuleNumber(pubNicRuleNo,
						fmt.Sprintf("outbound-interface %s", outNic),
						fmt.Sprintf("source address %s", address),
						"destination address !224.0.0.0/8",
						fmt.Sprintf("translation address %s", s.PublicIp),
					)
					update = true
				}
			}
			if priNicRuleNo == 0 {
				priNicRuleNo = newPriNicRuleNo
				priRs := tree.Getf("nat source rule %v", priNicRuleNo)
				if priRs == nil {
					tree.SetSnatWithRuleNumber(priNicRuleNo,
						fmt.Sprintf("outbound-interface %s", inNic),
						fmt.Sprintf("source address %v", address),
						"destination address !224.0.0.0/8",
						fmt.Sprintf("translation address %s", s.PublicIp),
					)
				}
				update = true
			}
		} else {
			pubNicRuleNo,priNicRuleNo = getNicSNATRuleNumberByConfig(tree, s)
			if rs := tree.Getf("nat source rule %v", pubNicRuleNo); rs != nil {
				update = true
				rs.Delete()
			}

			if rs := tree.Getf("nat source rule %v", priNicRuleNo); rs != nil {
				update = true
				rs.Delete()
			}
		}
	}

	tree.Apply(false)
	return update
}

func setSnatStateHandler(ctx *server.CommandContext) interface{} {
	cmd := &setSnatStateCmd{}
	ctx.GetCommand(cmd)
	
	return setSnatState(cmd)
}

func setSnatState(cmd *setSnatStateCmd) interface{} {
	if utils.IsSkipVyosIptables() {
		syncSnatByIptables(cmd.Snats, cmd.Enable)
	} else {
		update := applySnatRules(cmd.Snats, cmd.Enable)
		if update && len(cmd.Snats) > 0 {
			/* after snat is enabled, delete connections which is not snat */
			t := utils.ConnectionTrackTuple{IsNat: false, IsDst: true, Ip: cmd.Snats[0].PublicIp, Protocol: "",
				PortStart: 0, PortEnd: 0}
			t.CleanConnTrackConnection()
		}
	}

	if cmd.Enable {
		return setNetworkServiceRsp{ServiceStatus: "enable"}
	} else {
		t := utils.ConnectionTrackTuple{IsNat: true, IsDst: false, Ip: cmd.Snats[0].PublicIp, Protocol: "",
			PortStart: 0, PortEnd: 0}
		t.CleanConnTrackConnection()
		return setNetworkServiceRsp{ServiceStatus: "disable"}
	}
}

func syncSnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &syncSnatCmd{}
	ctx.GetCommand(cmd)
	
	return syncSnat(cmd)
}

func syncSnat(cmd *syncSnatCmd) interface{} {
	if utils.IsSkipVyosIptables() {
		syncSnatByIptables(cmd.Snats, cmd.Enable)
	} else {
		update := applySnatRules(cmd.Snats, cmd.Enable)
		if update && len(cmd.Snats) > 0 {
			/* after snat is enabled, delete connections which is not snat */
			t := utils.ConnectionTrackTuple{IsNat: false, IsDst: true, Ip: cmd.Snats[0].PublicIp, Protocol: "",
				PortStart: 0, PortEnd: 0}
			t.CleanConnTrackConnection()
		}
	}

	return nil
}

func SnatEntryPoint() {
	server.RegisterAsyncCommandHandler(SET_SNAT_PATH, server.VyosLock(setSnatHandler))
	server.RegisterAsyncCommandHandler(REMOVE_SNAT_PATH, server.VyosLock(removeSnatHandler))
	server.RegisterAsyncCommandHandler(SYNC_SNAT_PATH, server.VyosLock(syncSnatHandler))
	server.RegisterAsyncCommandHandler(SET_SNAT_STATE_PATH, server.VyosLock(setSnatStateHandler))
}
