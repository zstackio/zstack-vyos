package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	FirewallTable = "filter"
	NatTable      = "nat"
	MangleTable   = "mangle"
)

type IpTablesHelper interface {
	parseIpTableRule(rule *IpTableRule, priority int)
	getNextRuleNumber(t *IpTables, rule *IpTableRule) int
}

var vyosIptableHelper VyosIpTableHelper

type IpTableRule struct {
	priority      int
	ruleNumber    int
	compareTarget bool

	IpTableMatcher
	IpTableTarget
}

func NewIpTableRule(chainName string) *IpTableRule {
	var rule IpTableRule
	rule.chainName = chainName
	return &rule
}

/* firewall comment format: "system rule@eth1.in-1001 " */
func (r *IpTableRule) GetRuleNumber() int {
	return r.ruleNumber
}

func (r *IpTableRule) Copy() *IpTableRule {
	rule := *r
	copy(rule.states, r.states)
	copy(rule.tcpFlags, r.tcpFlags)
	return &rule
}

func (r *IpTableRule) String() string {
	return r.matcherString() + " " + r.targetString() + "\n"
}

func (r *IpTableRule) IsRuleEqual(o *IpTableRule) error {
	if err := r.isMatcherEqual(o); err != nil {
		return err
	}

	/* for some case, private ip can be nat to multiple public ip
	   only first rule work, secondary will work after 1st is deleted */
	if r.compareTarget || o.compareTarget {
		if err := r.IsTargetEqual(o); err != nil {
			return err
		} else {
			return nil
		}
	}

	return nil
}

func (r *IpTableRule) SetPriority(priority int) *IpTableRule {
	r.priority = priority
	return r
}

type IpTableChain struct {
	Name   string
	Action string
}

func (c *IpTableChain) String() string {
	return fmt.Sprintf(":%s %s\n", c.Name, c.Action)
}

func NewIpTablesChain(name string) *IpTableChain {
	return &IpTableChain{Name: name, Action: "-"}
}

type IpTables struct {
	Name   string
	Chains []*IpTableChain
	Rules  []*IpTableRule

	/* these fields only used for parse rules from iptables-save*/
	lastChainName      string
	priorityOfLastRule int
}

func NewIpTables(name string) *IpTables {
	table := &IpTables{Name: name, priorityOfLastRule: 0, lastChainName: ""}
	err := table.save()
	PanicOnError(err)

	return table
}

func (t *IpTables) parseIpTablesRule(line string) (*IpTableRule, error) {
	if !strings.HasPrefix(line, "-A") {
		log.Debugf("iptables rule prefix error %s", line)
		return nil, fmt.Errorf("iptables rule prefix error %s", line)
	}

	if !strings.Contains(line, "-j") {
		log.Debugf("iptables rule target error %s", line)
		return nil, fmt.Errorf("iptables rule target error %s", line)
	}

	var rule IpTableRule
	items := strings.Split(line, "-j")
	if _, err := rule.parseIpTablesMatcher(items[0], t.Chains); err != nil {
		return nil, err
	}

	if _, err := rule.parseIptablesTarget("-j " + items[1]); err != nil {
		return nil, err
	}

	if t.lastChainName != rule.chainName {
		t.priorityOfLastRule = 0
	}
	t.lastChainName = rule.chainName
	vyosIptableHelper.parseIpTableRule(&rule, t)
	t.priorityOfLastRule = rule.priority

	t.Rules = append(t.Rules, &rule)
	return &rule, nil
}

func (t *IpTables) parseIpTableChain(line string) (*IpTableChain, error) {
	items := strings.Fields(line)
	if len(items) < 2 {
		log.Debugf("parseIpTableChain %s faild", line)
		return nil, fmt.Errorf("iptable chain parse error %s", line)
	}

	chain := &IpTableChain{Name: items[0], Action: items[1]}
	t.Chains = append(t.Chains, chain)
	return chain, nil
}

func (t *IpTables) parseIpTables(rule string) error {
	lines := strings.Split(rule, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		switch line[0] {
		case '*':
			t.Name = line[1:]
			break

		case ':':
			if _, err := t.parseIpTableChain(line[1:]); err != nil {
				return err
			}
			break

		case '-':
			if _, err := t.parseIpTablesRule(line); err != nil {
				return err
			}
			break

		default:
			break
		}
	}

	return nil
}

func (t *IpTables) CheckChain(chainName string) bool {
	for _, c := range t.Chains {
		if strings.ToLower(c.Name) == strings.ToLower(chainName) {
			return true
		}
	}

	return false
}

func (t *IpTables) AddChain(chainName string) {
	found := false
	for _, c := range t.Chains {
		if c.Name == chainName {
			found = true
			break
		}
	}

	if !found {
		t.Chains = append(t.Chains, NewIpTablesChain(chainName))
	}
}

func (t *IpTables) DeleteChain(chainName string) {
	var chains []*IpTableChain

	for _, c := range t.Chains {
		if c.Name != chainName {
			chains = append(chains, NewIpTablesChain(c.Name))
		}
	}

	t.Chains = chains
}

func (t *IpTables) DeleteChainByKey(key string) {
	var chains []*IpTableChain

	for _, c := range t.Chains {
		if !strings.Contains(c.Name, key) {
			chains = append(chains, NewIpTablesChain(c.Name))
		}
	}

	t.Chains = chains
}

func (t *IpTables) GetChain(chainName string) *IpTableChain {
	for _, c := range t.Chains {
		if c.Name == chainName {
			return c
		}
	}

	return nil
}

func (t *IpTables) addIpTableRule(rule *IpTableRule) {
	var rules []*IpTableRule
	added := false

	rule.ruleNumber = vyosIptableHelper.getNextRuleNumber(t, rule)
	if rule.ruleNumber != 0 {
		rule.comment = getComment(rule)
	}

	for _, r := range t.Rules {
		if r.chainName != rule.chainName {
			rules = append(rules, r)
			continue
		}

		if r.priority < rule.priority {
			rules = append(rules, r)
			continue
		} else if r.priority == rule.priority {
			if r.IsRuleEqual(rule) == nil {
				rules = append(rules, rule)
				added = true
			} else {
				rules = append(rules, r)
			}
		} else {
			if !added {
				rules = append(rules, rule)
				added = true
			}
			rules = append(rules, r)
		}
	}

	if !added {
		rules = append(rules, rule)
	}

	t.Rules = rules
}

func (t *IpTables) AddIpTableRules(rules []*IpTableRule) {
	for _, r := range rules {
		t.addIpTableRule(r)
	}
}

func (t *IpTables) removeChainByPrefix(prefix []string) {
	if len(t.Chains) == 0 || len(prefix) == 0 {
		return
	}

	var chains []*IpTableChain
	for _, chain := range t.Chains {
		exclude := false
		for _, p := range prefix {
			if strings.Contains(chain.Name, p) {
				exclude = true
				continue
			}
		}

		if !exclude {
			chains = append(chains, chain)
		}
	}

	t.Chains = chains
}

func (t *IpTables) removeChainRules(chainName string) {
	/* remove */
	var chains []*IpTableChain
	for _, c := range t.Chains {
		if c.Name != chainName {
			chains = append(chains, c)
		}
	}

	t.Chains = chains

	/* remove rules */
	var rules []*IpTableRule
	for _, r := range t.Rules {
		if r.chainName == chainName {
			continue
		}

		if r.action == chainName {
			continue
		}

		rules = append(rules, r)
	}

	t.Rules = rules
}

func (t *IpTables) RemoveIpTableRule(newRules []*IpTableRule) {
	var rules []*IpTableRule
	for _, r := range t.Rules {
		found := false
		for _, nr := range newRules {
			if r.IsRuleEqual(nr) == nil {
				found = true
				break
			}
		}

		if !found {
			rules = append(rules, r)
		}
	}

	t.Rules = rules
}

func (t *IpTables) RemoveIpTableRuleByComments(comment string) {
	var rules []*IpTableRule
	for _, r := range t.Rules {
		if !strings.Contains(r.comment, comment) {
			rules = append(rules, r)
		}
	}

	t.Rules = rules
}

func (t *IpTables) Check(rule *IpTableRule) bool {
	temp2 := rule.Copy()
	temp2.comment = ""

	for _, r := range t.Rules {
		temp1 := r.Copy()
		temp1.comment = ""

		sort.Strings(temp1.states)
		sort.Strings(temp2.states)
		sort.Strings(temp1.tcpFlags)
		sort.Strings(temp2.tcpFlags)

		if strings.ToLower(temp1.String()) == strings.ToLower(temp2.String()) {
			return true
		}
	}

	return false
}

func (t *IpTables) Found(chainname, comment string) []*IpTableRule {
	var rules []*IpTableRule
	for _, r := range t.Rules {
		if r.chainName != chainname {
			continue
		}

		if strings.Contains(r.comment, comment) {
			rules = append(rules, r.Copy())
		}
	}

	return rules
}

func (t *IpTables) getPrefix() string {
	return "iptables -t " + t.Name + " "
}

func (t *IpTables) Apply() error {
	return t.restore()
}

func (t *IpTables) restore() error {
	if ok, _ := PathExists(GetZvrRootPath()); !ok {
		if err := MkdirForFile(GetZvrRootPath(), 0755); err != nil {
			log.Debugf("Create dir: %s failed", GetZvrRootPath())
			return err
		}
	}

	tmpFile, err := ioutil.TempFile(GetZvrRootPath(), "iptable-restore")
	if err != nil {
		log.Debugf("create iptable-restore temp file failed %s", err.Error())
		return err
	}

	defer os.Remove(tmpFile.Name())

	content := []string{"*" + t.Name + "\n"}
	for _, chain := range t.Chains {
		content = append(content, chain.String())
	}
	for _, rule := range t.Rules {
		content = append(content, rule.String())
	}
	content = append(content, "COMMIT\n")

	if _, err = tmpFile.Write([]byte(strings.Join(content, "\n"))); err != nil {
		log.Debugf("write to temp file failed %s, Rules: %s", content, err.Error())
		return err
	}

	if err := tmpFile.Close(); err != nil {
		log.Debugf("close temp file failed %s", err.Error())
		return err
	}

	cmd := Bash{
		Command: fmt.Sprintf("iptables-restore  -w --table=%s < %s", t.Name, tmpFile.Name()),
		Sudo:    true,
	}

	//log.Debugf("iptables-restore content: %s", content)
	_, _, _, err = cmd.RunWithReturn()
	if err != nil {
		log.Debugf("iptables-restore -w content: %s\n\niptables-restore failed: %+v", content, err)
		bash := Bash{
			Command: fmt.Sprintf("iptables-restore -w --table=%s < %s 2>&1 | grep 'Error occurred at line' | awk '{print $(NF)}' | xargs -i sed -n '{}p' %s", t.Name, tmpFile.Name(), tmpFile.Name()),
			Sudo:    true,
		}
		_, outStr, _, _ := bash.RunWithReturn()
		log.Debugf("Error occurred at table: %s, error rule: %s", t.Name, outStr)
		return err
	}

	return nil
}

func (t *IpTables) save() error {
	cmd := Bash{
		Command: fmt.Sprintf("iptables-save -t " + t.Name),
		Sudo:    true,
		NoLog:   true,
	}

	ret, o, _, err := cmd.RunWithReturn()
	if ret != 0 || err != nil {
		log.Debugf("iptables-save failed ret = %d, err: %s", ret, err)
		return fmt.Errorf("iptables-save failed ret = %d, err: %s", ret, err)
	}
	//log.Debugf("current iptables %s", o)

	t.Chains = []*IpTableChain{}
	t.Rules = []*IpTableRule{}
	return t.parseIpTables(o)
}

func (t *IpTables) Flush(chainName string) error {
	cmd := Bash{
		Command: fmt.Sprintf("iptables-save -t " + t.Name + " -F " + chainName),
		Sudo:    true,
		NoLog:   true,
	}

	ret, _, _, err := cmd.RunWithReturn()
	if ret != 0 || err != nil {
		log.Debugf("iptables-save failed ret = %d, err: %s", ret, err)
		return fmt.Errorf("iptables-save failed ret = %d, err: %s", ret, err)
	}

	t.Chains = []*IpTableChain{}
	t.Rules = []*IpTableRule{}
	return nil
}
