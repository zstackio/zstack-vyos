package plugin

import (
	"zvr/server"
	"zvr/utils"
	"fmt"
	log "github.com/Sirupsen/logrus"
)

const (
	SET_SNAT_PATH = "/setsnat"
	REMOVE_SNAT_PATH = "/removesnat"
	SYNC_SNAT_PATH = "/syncsnat"
)

type snatInfo struct {
	PublicNicMac string `json:"publicNicMac"`
	PublicIp string `json:"publicIp"`
	PrivateNicMac string `json:"privateNicMac"`
	PrivateNicIp string `json:"privateNicIp"`
	SnatNetmask string `json:"snatNetmask"`
}

type setSnatCmd struct {
	Snat snatInfo `json:"snat"`
}

type removeSnatCmd struct {
	NatInfo []snatInfo `json:"natInfo"`
}

type syncSnatCmd struct {
	Snats []snatInfo `json:"snats"`
}

var SNAT_RULE_NUMBER = 9999

func getNicSNATRuleNumber(nicNo int)  (ruleNo int){
	return SNAT_RULE_NUMBER - nicNo
}

func setSnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &setSnatCmd{}
	ctx.GetCommand(cmd)

	s := cmd.Snat
	tree := server.NewParserFromShowConfiguration().Tree
	outNic, err := utils.GetNicNameByMac(s.PublicNicMac); utils.PanicOnError(err)
	inNic, err := utils.GetNicNameByMac(s.PrivateNicMac); utils.PanicOnError(err)
	nicNumber, err := utils.GetNicNumber(inNic); utils.PanicOnError(err)
	address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask); utils.PanicOnError(err)

	if hasRuleNumberForAddress(tree, address, nicNumber) {
		return nil
	}

	// make source nat rule as the latest rule
	// in case there are EIP rules
	tree.SetSnatWithRuleNumber(getNicSNATRuleNumber(nicNumber),
		fmt.Sprintf("outbound-interface %s", outNic),
		fmt.Sprintf("source address %v", address),
		fmt.Sprintf("translation address %s", s.PublicIp),
	)

	tree.Apply(false)

	return nil
}

func removeSnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &removeSnatCmd{}
	ctx.GetCommand(&cmd)

	tree := server.NewParserFromShowConfiguration().Tree


	for _, s := range cmd.NatInfo {
		inNic, err := utils.GetNicNameByMac(s.PrivateNicMac); utils.PanicOnError(err)
		nicNumber, err := utils.GetNicNumber(inNic); utils.PanicOnError(err)
		rs := tree.Get(fmt.Sprintf("nat source rule %v", getNicSNATRuleNumber(nicNumber)))
		if rs == nil {
			log.Debugf(fmt.Sprintf("nat source rule %v not found", getNicSNATRuleNumber(nicNumber)))
			continue
		}

		rs.Delete()
	}

	tree.Apply(false)

	return nil
}

func hasRuleNumberForAddress(tree *server.VyosConfigTree, address string, nicNo int) bool {
	rs := tree.Get(fmt.Sprintf("nat source rule %v", getNicSNATRuleNumber(nicNo)))
	if rs == nil {
		return false
	}

	return true
}

func syncSnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &syncSnatCmd{}
	ctx.GetCommand(cmd)

	tree := server.NewParserFromShowConfiguration().Tree

	for _, s := range cmd.Snats {
		outNic, err := utils.GetNicNameByMac(s.PublicNicMac); utils.PanicOnError(err)
		inNic, err := utils.GetNicNameByMac(s.PrivateNicMac); utils.PanicOnError(err)
		nicNumber, err := utils.GetNicNumber(inNic); utils.PanicOnError(err)
		address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask); utils.PanicOnError(err)
		if rs := tree.Getf("nat source rule %v", getNicSNATRuleNumber(nicNumber)); rs != nil {
			rs.Delete()
		}

		tree.SetSnatWithRuleNumber(getNicSNATRuleNumber(nicNumber),
			fmt.Sprintf("outbound-interface %s", outNic),
			fmt.Sprintf("source address %s", address),
			fmt.Sprintf("translation address %s", s.PublicIp),
		)
	}

	tree.Apply(false)

	return nil
}

func SnatEntryPoint() {
	server.RegisterAsyncCommandHandler(SET_SNAT_PATH, server.VyosLock(setSnatHandler))
	server.RegisterAsyncCommandHandler(REMOVE_SNAT_PATH, server.VyosLock(removeSnatHandler))
	server.RegisterAsyncCommandHandler(SYNC_SNAT_PATH, server.VyosLock(syncSnatHandler))
}