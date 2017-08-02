package plugin

import (
	"zvr/server"
	"zvr/utils"
	"fmt"
	"strings"
	log "github.com/Sirupsen/logrus"
)

const (
	VR_CREATE_VIP = "/createvip"
	VR_REMOVE_VIP = "/removevip"
	VR_SET_VIP_QOS = "/setvipqos"
	VR_DELETE_VIP_QOS = "/deletevipqos"
	VR_SYNC_VIP_QOS = "/syncvipqos"
	VR_IFB = "ifb0"
)

type vipInfo struct {
	Ip string `json:"ip"`
	Netmask string `json:"netmask"`
	Gateway string `json:"gateway"`
	OwnerEthernetMac string `json:"ownerEthernetMac"`
}

type vipQosSettings struct {
	Ip                          string `json:"ip"`
	QosClassId                  int `json:"qosClassId"`
	VipUuid                     string `json:"vipUuid"`
	IsFirstSetInboundBandwidth  bool `json:"isFirstSetInboundBandwidth"`
	IsFirstSetOutboundBandwidth bool `json:"isFirstSetOutboundBandwidth"`
	InboundBandwidth            int64 `json:"inboundBandwidth"`
	OutBoundBandwidth           int64 `json:"outboundBandwidth"`
	NicMac						string `json:"nicMac"`
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

	return nil
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
	}

	tree.Apply(false)

	return nil
}

func setVipQos(ctx *server.CommandContext) interface{} {
	cmd := &setVipQosCmd{}
	ctx.GetCommand(cmd)

	for _, setting := range cmd.Settings {
		addr := fmt.Sprintf("%v/32", setting.Ip)
		publicInterface, err := utils.GetNicNameByIp(setting.Ip); utils.PanicOnError(err)
		if(setting.OutBoundBandwidth != -1 && setting.OutBoundBandwidth != 0){
			initPublicInterfaceQosConfigurationIfNotInit(publicInterface)
			addClass(publicInterface, setting.OutBoundBandwidth, setting.QosClassId)
			if(setting.IsFirstSetOutboundBandwidth){
				addOutFilter(publicInterface, addr, setting.QosClassId)
			}
		}

		if(setting.InboundBandwidth != -1 && setting.InboundBandwidth != 0){
			initIfbConfigurationIfNotInit(publicInterface)
			addClass(VR_IFB, setting.InboundBandwidth, setting.QosClassId)
			if(setting.IsFirstSetInboundBandwidth){
				addInFilter(VR_IFB, addr, setting.QosClassId)
			}
		}

	}

	return nil
}

func deleteVipQos(ctx *server.CommandContext) interface{} {
	cmd := &deleteVipQosCmd{}
	ctx.GetCommand(cmd)

	for _, setting := range cmd.Settings {
		publicInterface, error := utils.GetNicNameByIp(setting.Ip)
		if (error != nil && setting.NicMac != "") {
			log.Debugf("no nic for ip %s found, try to use mac %s", setting.Ip, setting.NicMac)
			publicInterface, error = utils.GetNicNameByMac(setting.NicMac); utils.PanicOnError(error)
		}
		if(setting.OutBoundBandwidth == 0){
			delFilter(publicInterface, setting.QosClassId)
			delClass(publicInterface, setting.QosClassId)
		}
		if(setting.InboundBandwidth == 0){
			delFilter(VR_IFB, setting.QosClassId)
			delClass(VR_IFB, setting.QosClassId)
		}
	}

	return nil
}

func syncVipQos(ctx *server.CommandContext) interface{} {
	cmd := &syncVipQosCmd{}
	ctx.GetCommand(cmd)

	for _, setting := range cmd.Settings {
		addr := fmt.Sprintf("%v/32", setting.Ip)
		publicInterface, err := utils.GetNicNameByIp(setting.Ip);
		if (err != nil && setting.NicMac != "") {
			log.Debugf("no nic for ip %s found, try to use mac %s", setting.Ip, setting.NicMac)
			publicInterface, err = utils.GetNicNameByMac(setting.NicMac); utils.PanicOnError(err)
		}
		initPublicInterfaceQosConfigurationIfNotInit(publicInterface)
		initIfbConfigurationIfNotInit(publicInterface)
		if(setting.OutBoundBandwidth != -1 && setting.OutBoundBandwidth != 0){
			addClass(publicInterface, setting.OutBoundBandwidth, setting.QosClassId)
			addOutFilter(publicInterface, addr, setting.QosClassId)
		}
		if(setting.InboundBandwidth != -1 && setting.InboundBandwidth != 0){
			addClass(VR_IFB, setting.InboundBandwidth, setting.QosClassId)
			addInFilter(VR_IFB, addr, setting.QosClassId)
		}
		if(setting.OutBoundBandwidth == 0){
			delFilter(publicInterface, setting.QosClassId)
			delClass(publicInterface, setting.QosClassId)
		}
		if(setting.InboundBandwidth == 0){
			delFilter(VR_IFB, setting.QosClassId)
			delClass(VR_IFB, setting.QosClassId)
		}
	}

	return nil
}

func addClass(nicName string, bandwidth int64, qosClassId int){
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo tc class replace dev %s parent 1: classid 1:%d htb rate %dbit ceil %dbit burst 10k cburst 10k", nicName, qosClassId, bandwidth, bandwidth),
	}
	bash.Run()
	bash.PanicIfError()
}

func delClass(nicName string, qosClassId int){
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo tc class del dev %s parent 1: classid 1:%d", nicName, qosClassId),
	}
	bash.Run()
	bash.PanicIfError()
}

func addOutFilter(nicName string, addr string, qosClassId int){
	bash := utils.Bash{
		Command:fmt.Sprintf("sudo tc filter replace dev %s parent 1: protocol ip prio 12 u32 match ip src %s flowid 1:%d", nicName, addr, qosClassId),
	}
	bash.Run()
	bash.PanicIfError()
}

func addInFilter(nicName string, addr string, qosClassId int){
	bash := utils.Bash{
		Command:fmt.Sprintf("sudo tc filter replace dev %s parent 1: protocol ip prio 12 u32 match ip dst %s flowid 1:%d", nicName, addr, qosClassId),
	}
	bash.Run()
	bash.PanicIfError()
}

func delFilter(nicName string, qosClassId int){
	bash := utils.Bash{
		Command:fmt.Sprintf("handles=`sudo tc filter list dev %s |grep \"flowid 1:%d\" |awk '{print $10}'`; for handle in $handles; do sudo tc filter delete dev %s parent 1: protocol ip prio 12 handle ${handle} u32; done", nicName, qosClassId, nicName),
	}
	bash.Run()
	bash.PanicIfError()
}

func initIfbConfigurationIfNotInit(pubInterface string){
	//init ifb
	bash :=utils.Bash{
		Command: "ip a |grep ifb | awk '{print $2}' |sed 's/\\://g'",
	}
	_,o,_,_ := bash.RunWithReturn();bash.PanicIfError()
	o = strings.TrimSpace(o)
	if(!strings.Contains(o, VR_IFB)){
		bash = utils.Bash{
			Command: fmt.Sprintf("/sbin/modprobe ifb numifbs=0;" +
				"ip link add %s type ifb;" +
				"ip link set dev %s up;", VR_IFB, VR_IFB,),
		}

		bash.Run()
		bash.PanicIfError()
	}

	//init public interface ingress
	bash = utils.Bash{
		Command: fmt.Sprintf("sudo tc qdisc show dev %s | awk '{print $2,$3}'", pubInterface),
	}
	_,o,_,_ = bash.RunWithReturn();bash.PanicIfError()
	if(!strings.Contains(o, "ingress ffff:")){
		bash = utils.Bash{
			Command: fmt.Sprintf("sudo tc qdisc add dev %s handle ffff: ingress",pubInterface),
		}
		bash.Run()
		bash.PanicIfError()
	}

	//init ifb qos configuration
	bash = utils.Bash{
		Command: fmt.Sprintf("sudo tc qdisc show dev %s| awk '{print $2,$3,$4}'", VR_IFB),
	}
	_,o,_,_ = bash.RunWithReturn();bash.PanicIfError()
	o = strings.TrimSpace(o)
	if(!strings.Contains(o,"htb 1: root")){
		bash = utils.Bash{
			Command: fmt.Sprintf("sudo tc qdisc add dev %s root handle 1:0 htb default a;" +
				"sudo tc filter add dev %s parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev %s", VR_IFB, pubInterface, VR_IFB),
		}
		bash.Run()
		bash.PanicIfError()
	}
}

func initPublicInterfaceQosConfigurationIfNotInit(pubInterface string){
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo tc qdisc show dev %s | awk '{print $2,$3,$4}'", pubInterface),
	}
	_,o,_,_ := bash.RunWithReturn(); bash.PanicIfError()
	o = strings.TrimSpace(o)
	if(!strings.Contains(o,"htb 1: root")){
		bash = utils.Bash{
			Command: fmt.Sprintf("sudo tc qdisc add dev %s root handle 1:0 htb default a", pubInterface),
		}
		bash.Run()
		bash.PanicIfError()
	}

}

func VipEntryPoint()  {
	server.RegisterAsyncCommandHandler(VR_CREATE_VIP, server.VyosLock(setVip))
	server.RegisterAsyncCommandHandler(VR_REMOVE_VIP, server.VyosLock(removeVip))
	server.RegisterAsyncCommandHandler(VR_SET_VIP_QOS, server.VyosLock(setVipQos))
	server.RegisterAsyncCommandHandler(VR_DELETE_VIP_QOS, server.VyosLock(deleteVipQos))
	server.RegisterAsyncCommandHandler(VR_SYNC_VIP_QOS, server.VyosLock(syncVipQos))
}
