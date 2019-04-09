package plugin

import (
	"zvr/server"
	"zvr/utils"
	"fmt"
	"strings"
	log "github.com/Sirupsen/logrus"
	"unicode"
	"bytes"
	"strconv"
	"sort"
	prom "github.com/prometheus/client_golang/prometheus"
)

const (
	VR_CREATE_VIP = "/createvip"
	VR_REMOVE_VIP = "/removevip"
	VR_SET_VIP_QOS = "/setvipqos"
	VR_DELETE_VIP_QOS = "/deletevipqos"
	VR_SYNC_VIP_QOS = "/syncvipqos"
	VR_IFB = "ifb"
	TC_MAX_CLASSID = 0xFFFF
	TC_MAX_FILTER = 0xFFF
	MAX_UINT32  = uint32(0xFFFFFFFF)
	MAX_PUBLIC_INTERFACE = 128

	/* 16G */
	MAX_BINDWIDTH = uint64(0x4FFFFFFFF)
)

type direction int
const (
	INGRESS 	direction = 0
	EGRESS		direction = 1
	DIRECTION_MAX   direction = 2
)

/* a single tc rule  */
type qosRule struct {
	/* each qos rule mapped to a htb class which is subclass of root
	   ###### htb root class
	 * tc qdisc replace dev eth0 root handle 1: htb default 1

	   ###### htb class for default traffic
	 * tc class add dev eth0 parent 1:0 classid 1:1 htb rate 10gbit ceil 10gbit

	   ###### htb class for first rule, cburst = rate/800, max 128k
	 * tc class add dev eth0 parent 1:0 classid 1:2 htb rate 1mbit ceil 1mbit burst 15k cburst 15k
         * tc qdisc add dev eth0 parent 1:2 sfq
	 */
	classId         uint32

	/* all tc filters is attached to htb class 1:0, there are 4095 filter handlers, each handle contains 4095 filters. Totally FFFFFF rules
	 * rules from same IP address will be put in same filter handler. so totally there will have 4095 ip address
	 * more IP addresses will be supported later
	 * */
	prioId          uint32
	filterId        uint32
	filterPos       uint32

	ip     		string
	port 		uint16
	bandwidth	uint64
	vipUuid         string
}

type qosRuleHook interface {
	AddRule(nic string, direct direction)
	DelRule(nic string, direct direction)
	AddFilter(nic string, direct direction)
	DelFilter(nic string, direct direction)
}

func (rule *qosRule) AddRule (nic string, direct direction) interface{} {
	bash := utils.Bash{
		Command:fmt.Sprintf("sudo tc qdisc del dev %s parent 1:%x;" +
			"sudo tc class del dev %s parent 1:0 classid 1:%x;",
			nic, rule.classId,
			nic, rule.classId),
	}
	bash.Run()

	bandwidth := rule.bandwidth;
	if (bandwidth <= 0) {
		bandwidth = 1
	}

	bash1 := utils.Bash{
		Command:fmt.Sprintf("sudo tc class add dev %s parent 1:0 classid 1:%x htb rate %d ceil %d burst 15k cburst 15k;" +
			"sudo tc qdisc add dev %s parent 1:%x sfq;",
			nic, rule.classId, bandwidth, bandwidth,
			nic, rule.classId),
	}
	bash1.Run()
	bash1.PanicIfError()

	rule.AddFilter(nic, direct)

	return nil
}

func (rule *qosRule) DelRule (nic string, direct direction) interface{} {
	bash := utils.Bash{
		Command:fmt.Sprintf("sudo tc filter del dev %s parent 1:0 prio %d handle %03x::%03x protocol ip u32;" +
			"sudo tc qdisc del dev %s parent 1:%x sfq;" +
			"sudo tc class del dev %s parent 1:0 classid 1:%x;",
			nic, rule.prioId, rule.filterId, rule.filterPos,
			nic, rule.classId,
			nic, rule.classId),
	}
	bash.Run()

	return nil
}

func (rule *qosRule) AddFilter (nic string, direct direction) interface{} {
	var bash utils.Bash
	rule.DelFilter(nic, direct)
	if (rule.port != 0) {
		if (direct == INGRESS) {
			bash = utils.Bash{
				Command:fmt.Sprintf(
					"sudo tc filter add dev %s parent 1:0 prio %d handle %03x::%03x protocol ip u32 match ip dst %s/32 match ip dport %d 0xffff flowid 1:%x",
					nic, rule.prioId, rule.filterId, rule.filterPos, rule.ip, rule.port, rule.classId),
			}
		} else {
			bash = utils.Bash{
				Command:fmt.Sprintf(
					"sudo tc filter add dev %s parent 1:0 prio %d handle %03x::%03x protocol ip u32 match ip src %s/32 match ip sport %d 0xffff flowid 1:%x",
					nic, rule.prioId, rule.filterId, rule.filterPos, rule.ip, rule.port, rule.classId),
			}
		}
	} else {
		if (direct == INGRESS) {
			bash = utils.Bash{
				Command:fmt.Sprintf(
					"sudo tc filter add dev %s parent 1:0 prio %d handle %03x::%03x protocol ip u32 match ip dst %s/32 flowid 1:%x",
					nic, rule.prioId, rule.filterId, rule.filterPos, rule.ip, rule.classId),
			}
		} else {
			bash = utils.Bash{
				Command:fmt.Sprintf(
					"sudo tc filter add dev %s parent 1:0 prio %d handle %03x::%03x protocol ip u32 match ip src %s/32 flowid 1:%x",
					nic, rule.prioId, rule.filterId, rule.filterPos, rule.ip, rule.classId),
			}
		}
	}
	bash.Run()
	bash.PanicIfError()

	return nil
}

func (rule *qosRule) DelFilter (nic string, direct direction) interface{} {
	bash := utils.Bash{
		Command:fmt.Sprintf("sudo tc filter del dev %s parent 1:0 prio %d handle %03x::%03x protocol ip u32",
			nic, rule.prioId, rule.filterId, rule.filterPos),
	}
	bash.Run()
	return nil
}

type Bitmap struct {
	bitmap []uint32
}
type bitmapHook interface {
	Init(int)
	AddNumber(uint32)
	DelNumber(uint32)
	FindFirstAvailable() uint32
	Reset()
}

func (bitmap *Bitmap) Init(length int)  {
	bitmap.bitmap = make([]uint32, length)
}

func (bitmap *Bitmap) AddNumber(number uint32) {
	pos := number >> 5
	if (pos >= uint32(len(bitmap.bitmap))) {
		return
	}
	bit := number - (pos << 5)
	(bitmap.bitmap)[pos] |= (1 << bit)
}

func (bitmap *Bitmap) DelNumber(number uint32) {
	pos := number >> 5
	if (pos >= uint32(len(bitmap.bitmap))) {
		return
	}
	bit := number - (pos << 5)
	(bitmap.bitmap)[pos] &= ^(1 << bit)
}

func (bitmap *Bitmap) FindFirstAvailable() uint32  {
	for i := 0; i < len(bitmap.bitmap); i++ {
		if (bitmap.bitmap[i] == 0xffffffff) {
			continue
		}
		for j := 0; j < 32; j++ {
			if (((bitmap.bitmap)[i] & (1 << uint32(j))) == 0) {
				return uint32((i << 5) + j);
			}
		}
	}
	return MAX_UINT32;
}

func (bitmap *Bitmap) Reset () {
	for i := 0; i < len(bitmap.bitmap); i++ {
		(bitmap.bitmap)[i] = 0
	}
}

/* all qos rules of same vip */
type vipQosRules struct {
	portRules      map[uint16]*qosRule
	vip            string
	prioId         uint32
	filterHandleID uint32
	filterMap      Bitmap
	vipUuid        string
}
type vipQosHook interface {
	VipQosRulesInit(string) interface{}
	VipQosAddRule (qosRule, string, direction) interface{}
	VipQosDelRule (qosRule, string, direction) interface{}
}

func (vipRules *vipQosRules) VipQosRulesInit(nicName string)  interface{} {

	/* generate the filter handler */
	filterBash := utils.Bash{
		Command: fmt.Sprintf("sudo tc filter add dev %s parent 1:0 prio %d protocol ip u32; " +
			"sudo tc filter show dev %s prio %d protocol ip | grep 'ht divisor'",
			nicName, vipRules.prioId,
			nicName, vipRules.prioId),
	}
	_,o,_,_ := filterBash.RunWithReturn();filterBash.PanicIfError()
	o = strings.TrimSpace(o)
	ids := strings.Split(o, "fh ");
	if (len(ids) == 1) {
		utils.PanicOnError(fmt.Errorf("can not find qos filter handler in %s", o))
	}
	ids = strings.Split(ids[1], ":")
	filterHandleID, err := strconv.ParseUint(ids[0], 16,32); utils.PanicOnError(err)
	vipRules.filterHandleID = uint32(filterHandleID)

	vipRules.filterMap.Init((TC_MAX_FILTER>>5)+1)
	vipRules.filterMap.AddNumber(0)
	vipRules.filterMap.AddNumber(TC_MAX_FILTER)

	log.Debugf("InitVipQosRule for ip %s for prioId %d filterHandleID %d",
		vipRules.vip, vipRules.prioId, vipRules.filterHandleID)

	return nil;
}

func (vipRules *vipQosRules) VipQosAddRule(rule qosRule, nicName string, direct direction) interface{} {
	rule.prioId = vipRules.prioId
	rule.filterId = vipRules.filterHandleID
	if (rule.port == 0) {
		rule.filterPos = TC_MAX_FILTER
	} else {
		/* when filterPos exceed the max, rule add will fail, so not handle here  */
		rule.filterPos = vipRules.filterMap.FindFirstAvailable()
		vipRules.filterMap.AddNumber(rule.filterPos)
	}

	rule.AddRule(nicName, direct)

	/* add rules to map */
	vipRules.portRules[rule.port] = &rule

	log.Debugf("AddRuleToInterface ip %s port %d, classId %d, prio %d, filter %03x:%03x, port number %d",
		rule.ip, rule.port, rule.classId, rule.prioId, rule.filterId, rule.filterPos, len(vipRules.portRules))

	return nil
}

func (vipRules *vipQosRules) VipQosDelRule(rule qosRule, nicName string, direct direction) interface{} {
	rule.DelRule(nicName, direct)

	/* clean data struct */
	vipRules.filterMap.DelNumber(rule.filterPos)
	delete(vipRules.portRules, rule.port)
	if (len(vipRules.portRules) ==0) {
		log.Debugf("DelRule clean ip %s prio %d", rule.ip, rule.prioId)
		/* delete filter */
		bash := utils.Bash{
			Command:fmt.Sprintf("sudo tc filter del dev %s parent 1:0 prio %d protocol ip u32",
				nicName, rule.prioId),
		}
		bash.Run()
		bash.PanicIfError()
		vipRules.filterMap.Reset()
	}
	log.Debugf("VipQosDelRule ip %s port %d, filterPos %d, remain port number %d", rule.ip, rule.port, rule.filterPos, len(vipRules.portRules))

	return nil
}

/* tc rules per interface per direction
 * rules       		#### 	map key is the vip ip, value is another map of rules of same vip
 * classBitmap      	#### 	record the classID used
 * fliterBitMap     	#### 	filter priority also use this id
 * cntMap               ####    map classId to vip ip
 */
type interfaceQosRules struct {
	name        string
	ifbName     string
	direct      direction
	rules       map[string]*vipQosRules
	classBitmap Bitmap
	prioBitMap  Bitmap
	classIdMap  map[uint32]string
}

type interfaceQosHook interface {
	InterfaceQosRulesInit() interface{}
	InterfaceQosRuleCleanUp() interface{}
	InterfaceQosRuleAddRule (qosRule) 	interface{}
	InterfaceQosRuleDelRule (qosRule)  	interface{}
	InterfaceQosRuleFind(qosRule) interface{}
}

func getInterfaceIndex(name string) string  {
	f := func(c rune) bool {
		return !unicode.IsNumber(c)
	}
	return strings.TrimFunc(name, f)
}

func (rules *interfaceQosRules) InterfaceQosRuleFind(newRule qosRule)  *qosRule {
	if _, ok := rules.rules[newRule.ip]; ok == false {
		return nil
	}

	if _, ok := rules.rules[newRule.ip].portRules[newRule.port]; ok == false {
		return nil
	}

	return rules.rules[newRule.ip].portRules[newRule.port]
}

func (rules *interfaceQosRules) InterfaceQosRuleInit(direct direction) interface{} {
	var name string
	rules.direct = direct
	/* reserve 0 for root class, 1 for default class */
	rules.classBitmap.Init((TC_MAX_CLASSID>>5) + 1)
	rules.classBitmap.Reset()
	rules.classBitmap.AddNumber(0)
	rules.classBitmap.AddNumber(1)
	rules.classBitmap.AddNumber(TC_MAX_CLASSID)
	rules.prioBitMap.Init((TC_MAX_CLASSID>>5) + 1)
	rules.prioBitMap.Reset()
	rules.prioBitMap.AddNumber(0)
	rules.prioBitMap.AddNumber(1)
	rules.prioBitMap.AddNumber(TC_MAX_CLASSID)
	rules.rules = make(map[string]*vipQosRules)
	rules.classIdMap = make(map[uint32]string)

	if (rules.direct == INGRESS) {
		/* get interface index */
		index := getInterfaceIndex(rules.name)
		if (len(index) == 0) {
			utils.PanicOnError(fmt.Errorf("Can not find index for interface: %s", rules.name))
			return nil
		}

		/* get ifb interface name */
		ifbName := bytes.NewBufferString ("")
		ifbName.WriteString(VR_IFB)
		ifbName.WriteString(index)
		rules.ifbName = ifbName.String()

		/* create ifb interface */
		tree := server.NewParserFromShowConfiguration().Tree
		if n := tree.Getf("interfaces input %s", rules.ifbName); n == nil {
			tree.SetfWithoutCheckExisting("interfaces input %s ", rules.ifbName)
		}

		/* redirect ingress to ifb */
		if n := tree.Getf("interfaces ethernet %s redirect", rules.name); n != nil {
			n.Delete()
		}
		tree.Setf("interfaces ethernet %s redirect %s", rules.name, rules.ifbName)
		tree.Apply(false)
		name = rules.ifbName
	} else {
		name = rules.name
	}

	log.Debugf("InitInterfaceQosRule for interface %s", name)
	/* apply htb to interface */
	bash := utils.Bash{
		Command:fmt.Sprintf("sudo tc qdisc del dev %s root;", name),
	}
	bash.Run()
	bash1 := utils.Bash{
		Command:fmt.Sprintf("sudo tc qdisc replace dev %s root handle 1: htb default 1;" +
			"sudo tc class add dev %s parent 1:0 classid 1:1 htb rate 10gbit ceil 10gbit;" +
			"sudo tc qdisc add dev %s parent 1:1 sfq", name, name, name),
	}
	bash1.Run()
	bash1.PanicIfError()

	return nil
}

func (rules *interfaceQosRules) InterfaceQosRuleCleanUp() interface{} {
	name := rules.name
	if (rules.direct == INGRESS) {
		name = rules.ifbName
	}

	log.Debugf("CleanupInterfaceQosRule for interface %s", name)
	/* apply del rules from interface */
	bash := utils.Bash{
		Command:fmt.Sprintf("sudo tc qdisc del dev %s root", name),
	}
	bash.Run()

	if (rules.direct == INGRESS) {
		tree := server.NewParserFromShowConfiguration().Tree
		if n := tree.Getf("interfaces ethernet %s redirect", rules.name); n != nil {
			n.Delete()
		}
		if n := tree.Getf("interfaces input %s", rules.ifbName); n == nil {
			n.Delete()
		}
		tree.Apply(false)
	}
	
	rules.classBitmap.Reset()
	rules.prioBitMap.Reset()

	return nil
}

func (rules *interfaceQosRules) InterfaceQosRuleAddRule(rule qosRule) interface{} {
	name := rules.name
	if (rules.direct == INGRESS ) {
		name = rules.ifbName
	}

	if _, vipOk := rules.rules[rule.ip]; vipOk == false {
		log.Debugf("AddRuleToInterface create map for ip %s", rule.ip)
		if (len(rules.rules) >= TC_MAX_FILTER) {
			utils.PanicOnError(fmt.Errorf("VipQos Reach the max number %d of interface %s ifbname %s",
				TC_MAX_FILTER, rules.name, rules.ifbName))
		}
		prioId := rules.prioBitMap.FindFirstAvailable()
		rules.prioBitMap.AddNumber(prioId)
		rules.rules[rule.ip] = &(vipQosRules{vip: rule.ip, prioId: prioId, portRules: make(map[uint16]*qosRule), vipUuid:rule.vipUuid})
		rules.rules[rule.ip].VipQosRulesInit(name)
	}

	if oldRule, portOk := rules.rules[rule.ip].portRules[rule.port]; portOk {
		/* delete old rule first */
		log.Debugf("AddRuleToInterface delete existed rule for ip %s port %d", rule.ip, rule.port)
		rules.InterfaceQosRuleDelRule(*oldRule)

		/* if this rule of this ip is the only rule for the vip*/
		if _, vipOk := rules.rules[rule.ip]; vipOk == false {
                        /* all rules of interface has been deleted */
                        if (len(rules.rules) == 0 ) {
                                rules.InterfaceQosRuleInit(rules.direct)
                        }

			log.Debugf("AddRuleToInterface create map for ip %s", rule.ip)
			if (len(rules.rules) >= TC_MAX_FILTER) {
				utils.PanicOnError(fmt.Errorf("VipQos Reach the max number %d of interface %s ifbname %s",
					TC_MAX_FILTER, rules.name, rules.ifbName))
			}
			prioId := rules.prioBitMap.FindFirstAvailable()
			rules.prioBitMap.AddNumber(prioId)
			rules.rules[rule.ip] = &(vipQosRules{vip: rule.ip, prioId: prioId, portRules: make(map[uint16]*qosRule), vipUuid:rule.vipUuid})
			rules.rules[rule.ip].VipQosRulesInit(name)
		}
	}

	classId := rules.classBitmap.FindFirstAvailable()
	if (classId == MAX_UINT32) {
		utils.PanicOnError(fmt.Errorf("Qos class is full for interface %s ifbname %s", rules.name, rules.ifbName))
	}
	rules.classBitmap.AddNumber(classId)
	rule.classId = classId
	rules.classIdMap[classId] = rule.ip

	rules.rules[rule.ip].VipQosAddRule(rule, name, rules.direct)

	log.Debugf("AddRuleToInterface rule ip %s, port %d, bandwith %d on interface %s, vip number %d",
		rule.ip, rule.port, rule.bandwidth, rules.name, len(rules.rules))

	return nil
}

func (rules *interfaceQosRules) InterfaceQosRuleDelRule(rule qosRule) interface{} {
	/* find qos rule */
	if _, vipOk := rules.rules[rule.ip]; (!vipOk) {
		log.Debugf("Vyos can not find rule for vip [ip:%s]", rule.ip)
		return nil
	}

	if _, portOK := rules.rules[rule.ip].portRules[rule.port]; (!portOK) {
		log.Debugf("Vyos can not find rule for vip [ip:%s, port: %d]", rule.ip, rule.port)
		return nil
	}

	/* delete rules */
	name := rules.name
	if (rules.direct == INGRESS) {
		name = rules.ifbName
	}

	classId := rules.rules[rule.ip].portRules[rule.port].classId
	rules.rules[rule.ip].VipQosDelRule(*rules.rules[rule.ip].portRules[rule.port], name, rules.direct)
	delete(rules.classIdMap, classId)

	rules.classBitmap.DelNumber(classId)
	if (len(rules.rules[rule.ip].portRules) ==0) {
		rules.prioBitMap.DelNumber(rules.rules[rule.ip].prioId)
		delete(rules.rules, rule.ip)
		if (len(rules.rules) == 0) {
			/* clean data struct to avoid classid overflow */
			log.Debugf("DelRuleFromInterface clean interface %s", name)
			rules.InterfaceQosRuleCleanUp()
		}
	}

	log.Debugf("DelRule for ip %s port %d, classid %d, name %s, remain vip number %d", rule.ip, rule.port, classId, name, len(rules.rules))
	return nil
}

/* var for qos rules of all interfaces */
type interfaceInOutQosRules [DIRECTION_MAX]*interfaceQosRules
var totalQosRules map[string]interfaceInOutQosRules

func addQosRule(publicInterface string, direct direction, qosRule qosRule) interface{} {
	if _, ok := totalQosRules[publicInterface]; !ok {
		log.Debugf("init data struct for %s", publicInterface)
		totalQosRules[publicInterface] = interfaceInOutQosRules([DIRECTION_MAX]*interfaceQosRules{
			&(interfaceQosRules{name: publicInterface}), &(interfaceQosRules{name: publicInterface})})
	}

	log.Debugf("addQosRule add rule to map of publicInterface: %s direct %d", publicInterface, direct)
	if (len(totalQosRules[publicInterface][direct].rules) == 0) {
		log.Debugf("addQosRule init data struct for %s dirct %d", publicInterface, direct)
		totalQosRules[publicInterface][direct].InterfaceQosRuleInit(direct)
	}
	totalQosRules[publicInterface][direct].InterfaceQosRuleAddRule(qosRule)

	return nil
}

func delQosRule(publicInterface string, direct direction, qosRule qosRule) interface{} {
	if _, ok := totalQosRules[publicInterface]; !ok {
		log.Debugf("Can not find qos rules for interface %s", publicInterface)
		return nil
	}

	log.Debugf("delQosRule publicInterface %s, direct %d, ip %s, port %d",
		publicInterface, direct, qosRule.ip, qosRule.port)
	totalQosRules[publicInterface][direct].InterfaceQosRuleDelRule(qosRule)

	return nil
}

func deleteQosRulesOfVip(publicInterface string, vip string)  {
	if _, ok := totalQosRules[publicInterface]; ok {
		if _, rok := totalQosRules[publicInterface][INGRESS].rules[vip]; rok {
			for _, rule := range totalQosRules[publicInterface][INGRESS].rules[vip].portRules {
				totalQosRules[publicInterface][INGRESS].InterfaceQosRuleDelRule(*rule)
			}
		}

		if _, rok := totalQosRules[publicInterface][EGRESS].rules[vip]; rok {
			for _, rule := range totalQosRules[publicInterface][EGRESS].rules[vip].portRules {
				totalQosRules[publicInterface][EGRESS].InterfaceQosRuleDelRule(*rule)
			}
		}

		if ((len(totalQosRules[publicInterface][INGRESS].rules) == 0) &&
			(len(totalQosRules[publicInterface][EGRESS].rules) == 0)) {
			delete(totalQosRules, publicInterface)
		}
	}
}

type vipInfo struct {
	Ip string `json:"ip"`
	Netmask string `json:"netmask"`
	Gateway string `json:"gateway"`
	OwnerEthernetMac string `json:"ownerEthernetMac"`
	Nic string `json:"nic"`             /* this is used for delete */
	VipUuid string `json:"vipUuid"`
}

type vipQosSettings struct {
	Vip                          string `json:"vip"`
	VipUuid                     string `json:"vipUuid"`
	Port                        int   `json:"port"`
	InboundBandwidth            int64 `json:"inboundBandwidth"`
	OutboundBandwidth           int64 `json:"outboundBandwidth"`
	Type                        string `json:"type"`
	HasVipQos                   bool   `json:"hasVipQos"`
}

type setVipCmd struct {
	Vips []vipInfo `json:"vips"`
}

type removeVipCmd struct {
	Vips []vipInfo `json:"vips"`
}

type setVipQosCmd struct {
	Settings []vipQosSettings `json:"vipQosSettings"`

}

type deleteVipQosCmd struct {
	Settings []vipQosSettings `json:"vipQosSettings"`
}

type syncVipQosCmd struct {
	Settings []vipQosSettings `json:"vipQosSettings"`
}

type vipQosSettingsArray []vipQosSettings
func (a vipQosSettingsArray) Len() int           { return len(a) }
func (a vipQosSettingsArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a vipQosSettingsArray) Less(i, j int) bool { return a[i].Port > a[j].Port }

func setVip(ctx *server.CommandContext) interface{} {
	cmd := &setVipCmd{}
	ctx.GetCommand(cmd)

	tree := server.NewParserFromShowConfiguration().Tree
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac); utils.PanicOnError(err)
		cidr, err := utils.NetmaskToCIDR(vip.Netmask); utils.PanicOnError(err)
		addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)
		if n := tree.Getf("interfaces ethernet %s address %v", nicname, addr); n == nil {
			tree.SetfWithoutCheckExisting("interfaces ethernet %s address %v", nicname, addr)
		}
	}

	tree.Apply(false)

	/* ad default qos for vip traffic counter */
	for _, vip := range cmd.Vips {
		publicInterface, err := utils.GetNicNameByIp(vip.Ip); utils.PanicOnError(err)
		ingressrule := qosRule{ip: vip.Ip, port: 0, bandwidth: MAX_BINDWIDTH, vipUuid: vip.VipUuid}
		if biRule, ok := totalQosRules[publicInterface]; ok {
			if biRule[INGRESS].InterfaceQosRuleFind(ingressrule) == nil {
				addQosRule(publicInterface, INGRESS, ingressrule)
			}
		} else {
			addQosRule(publicInterface, INGRESS, ingressrule)
		}

		egressrule := qosRule{ip: vip.Ip, port: 0, bandwidth: MAX_BINDWIDTH, vipUuid: vip.VipUuid}
		if biRule, ok := totalQosRules[publicInterface]; ok {
			if biRule[EGRESS].InterfaceQosRuleFind(egressrule) == nil {
				addQosRule(publicInterface, EGRESS, egressrule)
			}
		} else {
			addQosRule(publicInterface, EGRESS, egressrule)
		}
	}

	return nil
}

func getDeleteFailVip (info []vipInfo) ([]vipInfo) {
	toDeletelVip := []vipInfo{}
	for _, vip := range info {
		nic, err := utils.GetNicNameByIp(vip.Ip)
		if (err == nil) {
			vip.Nic = nic
			toDeletelVip = append(toDeletelVip, vip)
		}
	}

	return toDeletelVip
}

func removeVip(ctx *server.CommandContext) interface{} {
	cmd := &removeVipCmd{}
	ctx.GetCommand(cmd)

	tree := server.NewParserFromShowConfiguration().Tree
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac); utils.PanicOnError(err)
		cidr, err := utils.NetmaskToCIDR(vip.Netmask); utils.PanicOnError(err)
		addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)

		tree.Deletef("interfaces ethernet %s address %v", nicname, addr)

		deleteQosRulesOfVip(nicname, vip.Ip)
	}

	tree.Apply(false)

	/* find vip delete failed */
	toDeletelVip := getDeleteFailVip(cmd.Vips)
	err := utils.Retry(func() error {
		for _, vip := range toDeletelVip {
			cidr, err := utils.NetmaskToCIDR(vip.Netmask); utils.PanicOnError(err)
			bash := utils.Bash {
				Command: fmt.Sprintf("sudo ip add del %s/%s dev %s ", vip.Ip, cidr, vip.Nic),
			}
			bash.Run()
		}

		toDeletelVip := getDeleteFailVip(toDeletelVip)
		if (len(toDeletelVip) == 0) {
			return nil
		} else {
			return fmt.Errorf("delete vips address %v failed", toDeletelVip)
		}
	}, 3, 1);utils.LogError(err)

	return nil
}

func setVipQos(ctx *server.CommandContext) interface{} {
	cmd := &setVipQosCmd{}
	ctx.GetCommand(cmd)

	/* sort will make sure vip with port rule is added first to avoid adjust filter position */
	sort.Sort(vipQosSettingsArray(cmd.Settings))
	for _, setting := range cmd.Settings {
		publicInterface, err := utils.GetNicNameByIp(setting.Vip); utils.PanicOnError(err)
		if (setting.InboundBandwidth != 0) {
			ingressrule := qosRule{ip: setting.Vip, port: uint16(setting.Port), bandwidth: uint64(setting.InboundBandwidth),
				vipUuid: setting.VipUuid}
			addQosRule(publicInterface, INGRESS, ingressrule)
		}
		if (setting.OutboundBandwidth != 0) {
			egressrule := qosRule{ip: setting.Vip, port: uint16(setting.Port), bandwidth: uint64(setting.OutboundBandwidth),
				vipUuid: setting.VipUuid}
			addQosRule(publicInterface, EGRESS, egressrule)
		}
	}

	return nil
}

func deleteVipQos(ctx *server.CommandContext) interface{} {
	cmd := &deleteVipQosCmd{}
	ctx.GetCommand(cmd)

        /* port 0 will not be deleted, but changed bandwidth to MAX_BINDWIDTH */
	sort.Sort(vipQosSettingsArray(cmd.Settings))
	for _, setting := range cmd.Settings {
		if (setting.Port == 0) {
                        continue
                }

		publicInterface, error := utils.GetNicNameByIp(setting.Vip);utils.PanicOnError(error)
		qosRule := qosRule{ip: setting.Vip, port: uint16(setting.Port), vipUuid: setting.VipUuid}
		delQosRule(publicInterface, INGRESS, qosRule)
		delQosRule(publicInterface, EGRESS, qosRule)
	}

        for _, setting := range cmd.Settings {
                if (setting.Port != 0) {
                        continue
                }

                publicInterface, error := utils.GetNicNameByIp(setting.Vip);utils.PanicOnError(error)
                qosRule := qosRule{ip: setting.Vip, port: 0, bandwidth: MAX_BINDWIDTH, vipUuid: setting.VipUuid}
                addQosRule(publicInterface, INGRESS, qosRule)
                addQosRule(publicInterface, EGRESS, qosRule)
        }

	return nil
}

func syncVipQos(ctx *server.CommandContext) interface{} {
	cmd := &syncVipQosCmd{}
	ctx.GetCommand(cmd)

	sort.Sort(vipQosSettingsArray(cmd.Settings))
	for _, setting := range cmd.Settings {
		publicInterface, err := utils.GetNicNameByIp(setting.Vip);utils.PanicOnError(err)
		if (setting.InboundBandwidth != 0) {
			ingressrule := qosRule{ip: setting.Vip, port: uint16(setting.Port), bandwidth: uint64(setting.InboundBandwidth),
				vipUuid: setting.VipUuid}
			if biRule, ok := totalQosRules[publicInterface]; !ok {
				if biRule[INGRESS].InterfaceQosRuleFind(ingressrule) == nil {
					addQosRule(publicInterface, INGRESS, ingressrule)
				}
			} else {
				addQosRule(publicInterface, INGRESS, ingressrule)
			}
		}

		if (setting.OutboundBandwidth != 0) {
			egressrule := qosRule{ip: setting.Vip, port: uint16(setting.Port), bandwidth: uint64(setting.OutboundBandwidth),
				vipUuid:setting.VipUuid}
			if biRule, ok := totalQosRules[publicInterface]; !ok {
				if biRule[EGRESS].InterfaceQosRuleFind(egressrule) == nil {
					addQosRule(publicInterface, EGRESS, egressrule)
				}
			} else {
				addQosRule(publicInterface, EGRESS, egressrule)
			}
		}
	}

	return nil
}


func init() {
	RegisterPrometheusCollector(NewVipPrometheusCollector())
}

type vipCollector struct {
	inByteEntry *prom.Desc
	inPktEntry *prom.Desc
	outByteEntry *prom.Desc
	outPktEntry *prom.Desc

	vipUUIds map[string]string
}

const (
	LABEL_VIP_UUID = "VipUUID"
)

func NewVipPrometheusCollector() MetricCollector {
	return &vipCollector{
		inByteEntry: prom.NewDesc(
			"zstack_vip_in_bytes",
			"VIP inbound traffic in bytes",
			[]string{LABEL_VIP_UUID}, nil,
		),
		inPktEntry: prom.NewDesc(
			"zstack_vip_in_packages",
			"VIP inbound traffic packages",
			[]string{LABEL_VIP_UUID}, nil,
		),
		outByteEntry: prom.NewDesc(
			"zstack_vip_out_bytes",
			"VIP outbound traffic in bytes",
			[]string{LABEL_VIP_UUID}, nil,
		),
		outPktEntry: prom.NewDesc(
			"zstack_vip_out_packages",
			"VIP outbound traffic packages",
			[]string{LABEL_VIP_UUID}, nil,
		),

		vipUUIds: make(map[string]string),
	}
}

func (c *vipCollector) Describe(ch chan<- *prom.Desc) error {
	ch <- c.inByteEntry
	ch <- c.inPktEntry
	ch <- c.outByteEntry
	ch <- c.outPktEntry
	return nil
}

type monitoringRule struct {
	pkts uint64
	bytes uint64
	source string
	destination string
	vipUuid     string
}

func (c *vipCollector) Update(ch chan<- prom.Metric) error {
	rules := getMonitoringRules(INGRESS)
	for _, rule := range rules {
		vipUuid := rule.vipUuid
		ch <- prom.MustNewConstMetric(c.outByteEntry, prom.GaugeValue, float64(rule.bytes), vipUuid)
		ch <- prom.MustNewConstMetric(c.outPktEntry, prom.GaugeValue, float64(rule.pkts), vipUuid)
	}

	rules = getMonitoringRules(EGRESS)
	for _, rule := range rules {
		vipUuid := rule.vipUuid
		ch <- prom.MustNewConstMetric(c.inByteEntry, prom.GaugeValue, float64(rule.bytes), vipUuid)
		ch <- prom.MustNewConstMetric(c.inPktEntry, prom.GaugeValue, float64(rule.pkts), vipUuid)
	}

	return nil
}

/*
output example
# tc -s class show dev eth0 | grep -A 1 'class htb'
class htb 1:1 root leaf 8003: prio 0 rate 10000Mbit ceil 10000Mbit burst 0b cburst 0b
 Sent 353013 bytes 2725 pkt (dropped 0, overlimits 0 requeues 0)
--
class htb 1:2 root leaf 8004: prio 0 rate 100000Kbit ceil 100000Kbit burst 15337b cburst 15337b
 Sent 29400 bytes 300 pkt (dropped 0, overlimits 0 requeues 0)
--
*/
func getInterfaceMonitorRules(direct direction, qosRules *interfaceQosRules) map[string]*monitoringRule  {
	name := qosRules.name
	if direct == INGRESS {
		name = qosRules.ifbName
	}

	bash := &utils.Bash{
		Command: fmt.Sprintf("sudo tc -s class show dev %s | grep -A 1 'class htb'", name),
		NoLog: true,
	}
	ret, stdout, _, _ := bash.RunWithReturn()
	if (ret != 0 ){
		return nil
	}

	lines := strings.Split(stdout, "\n")
	var cnt, classId uint32
	var byteCnt, pktCnt uint64
	var vipIp string
	var vipOk bool
	monitorRules := make(map[string]*monitoringRule)

	for _, line := range lines {
		switch cnt {
		case 0:
			strs := strings.Split(line, " ")
			classStr := strings.Split(strs[2], ":")
			id, _ := strconv.ParseUint(strings.Trim(classStr[1], " "), 10, 64)
			classId = (uint32)(id)
			/* in case class delete fail, just skip lines for this classid */
			vipIp, vipOk = qosRules.classIdMap[classId]
			cnt++;
			break;
		case 1:
			if (vipOk) {
				strs := strings.Split(strings.Trim(line, " "), " ")
				byteCnt, _ = strconv.ParseUint(strings.Trim(strs[1], " "), 10, 64)
				pktCnt, _ = strconv.ParseUint(strings.Trim(strs[3], " "), 10, 64)
			}
			cnt++;
			break;
		case 2:
			if (vipOk) {
				if qosRule, ok := qosRules.rules[vipIp]; ok {
					vipUuid := qosRule.vipUuid
					if _, ok := monitorRules[vipUuid]; !ok {
						monitorRules[vipUuid] = &monitoringRule{}
					}
					monitorRule := monitorRules[vipUuid]
					monitorRule.pkts += pktCnt
					monitorRule.bytes += byteCnt
					monitorRule.vipUuid = vipUuid

					if (direct == INGRESS) {
						monitorRule.destination = qosRules.rules[vipIp].vip
					} else {
						monitorRule.source = qosRules.rules[vipIp].vip
					}
				}
			}
			cnt = 0
			classId = 0
			vipOk = false
			byteCnt = 0
			pktCnt = 0
			break;
		default:
			cnt = 0
			classId = 0
			vipOk = false
			byteCnt = 0
			pktCnt = 0
			break;
		}
	}

	return monitorRules
}

func getMonitoringRules(direct direction) map[string]*monitoringRule {
	monitoringRules := make(map[string]*monitoringRule)
	for _, biRules := range totalQosRules {
		rules := getInterfaceMonitorRules(direct, biRules[direct])
		for k, v := range rules {
			monitoringRules[k] = v
		}
	}

	return monitoringRules
}

func VipEntryPoint()  {
	totalQosRules = make(map[string]interfaceInOutQosRules, MAX_PUBLIC_INTERFACE)
	server.RegisterAsyncCommandHandler(VR_CREATE_VIP, server.VyosLock(setVip))
	server.RegisterAsyncCommandHandler(VR_REMOVE_VIP, server.VyosLock(removeVip))
	server.RegisterAsyncCommandHandler(VR_SET_VIP_QOS, server.VyosLock(setVipQos))
	server.RegisterAsyncCommandHandler(VR_DELETE_VIP_QOS, server.VyosLock(deleteVipQos))
	server.RegisterAsyncCommandHandler(VR_SYNC_VIP_QOS, server.VyosLock(syncVipQos))
}
