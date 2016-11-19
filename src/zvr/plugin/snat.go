package plugin

import (
	"zvr/server"
	"zvr/utils"
	"fmt"
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

func setSnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &setSnatCmd{}
	ctx.GetCommand(cmd)

	s := cmd.Snat
	tree := server.NewParserFromShowConfiguration().Tree
	outNic, err := utils.GetNicNameByMac(s.PublicNicMac); utils.PanicOnError(err)
	address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask); utils.PanicOnError(err)

	if hasRuleNumberForAddress(tree, address) {
		return nil
	}

	// make source nat rule as the latest rule
	// in case there are EIP rules
	tree.SetSnatWithRuleNumber(SNAT_RULE_NUMBER,
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
	rs := tree.Get("nat source rule")
	if rs == nil {
		return nil
	}

	for _, s := range cmd.NatInfo {
		address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask); utils.PanicOnError(err)

		for _, r := range rs.Children() {
			if addr := r.Get("source address"); addr != nil && addr.Value() == address {
				addr.Delete()
			}
		}
	}

	tree.Apply(false)

	return nil
}

func hasRuleNumberForAddress(tree *server.VyosConfigTree, address string) bool {
	rs := tree.Get("nat source rule")
	if rs == nil {
		return false
	}

	for _, r := range rs.Children() {
		if addr := r.Get("source address"); addr != nil && addr.Value() == address {
			return true
		}
	}

	return false
}

func syncSnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &syncSnatCmd{}
	ctx.GetCommand(cmd)

	tree := server.NewParserFromShowConfiguration().Tree
	utils.Assert(len(cmd.Snats) < 2, "multiple source nat are not supported yet")

	for _, s := range cmd.Snats {
		outNic, err := utils.GetNicNameByMac(s.PublicNicMac); utils.PanicOnError(err)
		address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask); utils.PanicOnError(err)
		if rs := tree.Getf("nat source rule %v", SNAT_RULE_NUMBER); rs != nil {
			rs.Delete()
		}

		tree.SetSnatWithRuleNumber(SNAT_RULE_NUMBER,
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