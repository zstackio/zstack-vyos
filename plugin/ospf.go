package plugin

import (
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"strings"
	"unicode"
	"net"
)

const (
	ROUTER_PROTOCOL_REFRESH_OSPF = "/routerprotocol/ospf/refresh"
	ROUTER_PROTOCOL_GET_OSPF_NEIGHBOR = "/routerprotocol/ospf/neighbor"

	FIREWALL_DESCRIPTION = "ospf-firewall"
	SNAT_DESCRIPTION = "ospf-snat"
)

type RouterAreaType string
type RouterAreaAuthType string
const (
	Standard RouterAreaType = "Standard"
	Stub 	 RouterAreaType = "Stub"
	NSSA 	 RouterAreaType = "NSSA"
)
const (
	None 	  RouterAreaAuthType = "None"
	MD5 	  RouterAreaAuthType = "MD5"
	Plaintext RouterAreaAuthType = "Plaintext"
)

type areaInfo struct {
	AreaId string `json:"areaId"`
	AreaType RouterAreaType `json:"type"`
	AuthType RouterAreaAuthType `json:"authType"`
	AuthParam string `json:"authParam"`
}

type networkInfo struct {
	NicMac string `json:"nicMac"`
	Network string `json:"network"`
	AreaId string `json:"areaId"`
}

type setOspfCmd struct {
	RouterId string `json:"routerId"`
	AreaInfos []areaInfo `json:"areaInfos"`
	NetworkInfos []networkInfo `json:"networkInfos"`
}

type neighbor struct {
	Id string  `json:"id"`
	Priority string `json:"priority"`
	State string `json:"state"`
	DeadTime string `json:"deadTime"`
	NeighborAddress string `json:"neighborAddress"`
	Device string `json:"device"`
}
type getOspfNeighborRsp struct {
	Neighbors []neighbor `json:"neighbors"`
}

type protocol interface {
	init(*server.VyosConfigTree) (err error)
	setRouterId()  ( err error)
	setArea() ( error)
	setNetwork() ( err error)
	setRawCmd(f string, args...interface{}) (err error)
	delRawCmd(f string, args...interface{}) (err error)
	getNeighbors() ([]neighbor, error)
	commit() (err error)
}

// the ospf protocol implement
type ospfProtocol struct {
	Id string
	AreaInfos []areaInfo
	NetworkInfos []networkInfo
	Tree *server.VyosConfigTree
	CurrentArea map[string][]string
	CurrentOspfIntfs []string
	ToBeDeletedOspfIntfs []string
}

func (ospf *ospfProtocol) getCurrentConfig()  {
	ospf.CurrentArea = make(map[string][]string)
	ospf.CurrentOspfIntfs = []string{}
	ospf.ToBeDeletedOspfIntfs = []string{}
	anode := ospf.Tree.Getf("protocols ospf area")
	if anode != nil {
		for _, areaId := range anode.ChildNodeKeys() {
			nnode := ospf.Tree.Getf("protocols ospf area %s network", areaId)
			if nnode != nil {
				ospf.CurrentArea[areaId] = nnode.ChildNodeKeys()
			} else {
				ospf.CurrentArea[areaId] = []string{}
			}
		}
	}

	if nics, nicErr := utils.GetAllNics(); nicErr == nil {
		for _, nic := range nics {
			onode := ospf.Tree.Getf("interfaces ethernet %s ip ospf", nic.Name)
			if onode != nil {
				ospf.CurrentOspfIntfs = append(ospf.CurrentOspfIntfs, nic.Name)
			}
		}
	}

	newOspfIntf := map[string]string{}
	for _, n := range ospf.NetworkInfos {
		nic, _ := utils.GetNicNameByMac(n.NicMac)
		newOspfIntf[nic] = nic
	}
	for _, nic := range ospf.CurrentOspfIntfs {
		if _, ok := newOspfIntf[nic]; !ok {
			ospf.ToBeDeletedOspfIntfs = append(ospf.ToBeDeletedOspfIntfs, nic)
		}
	}
}

func (this *ospfProtocol) init(tree *server.VyosConfigTree)  ( err error) {
	err = nil
	this.Tree = tree
	/* clear all the configure of OSPF
	*/
	this.getCurrentConfig()
	if len(this.AreaInfos) > 0 {
		return
	}

	this.Tree.Deletef("protocols ospf")
	if nics, nicErr := utils.GetAllNics(); nicErr == nil {
		for _, nic := range nics {
			this.Tree.Deletef("interfaces ethernet %s ip ospf", nic.Name)

			if r := this.Tree.FindFirewallRuleByDescription(nic.Name, "in", FIREWALL_DESCRIPTION); r != nil {
				r.Delete()
			}
			if r := this.Tree.FindFirewallRuleByDescription(nic.Name, "local", FIREWALL_DESCRIPTION); r != nil {
				r.Delete()
			}
			if r := this.Tree.FindSnatRuleDescription(fmt.Sprintf("%s-%s", SNAT_DESCRIPTION, nic.Name)); r != nil {
				r.Delete()
			}
		}
	}
	return err
}

func (this *ospfProtocol) setRouterId()  ( err error) {
	if this.Tree == nil {
		panic(fmt.Errorf("missing initial"))
	}
	this.Tree.Setf("protocols ospf parameters router-id %s", this.Id)

	return nil;
}

func (this *ospfProtocol) setArea()  ( err error) {
	if this.Tree == nil {
		panic(fmt.Errorf("missing initial.."))
	}

	for areaId, _ := range this.CurrentArea {
		deleted := true
		for _, info := range this.AreaInfos {
			if info.AreaId == areaId {
				deleted = false
				break
			}
		}

		if deleted {
			this.Tree.Deletef("protocols ospf area %s", areaId)
		}
	}

	for _, info := range this.AreaInfos {
		if info.AreaType == Standard {
			this.Tree.Setf("protocols ospf area %s area-type %s", info.AreaId, "normal")
		} else if info.AreaType == NSSA {
			this.Tree.Setf("protocols ospf area %s area-type %s", info.AreaId, "nssa")
		} else {
			this.Tree.Setf("protocols ospf area %s area-type %s", info.AreaId, "stub")
		}

		if info.AuthType == Plaintext {
			this.Tree.Setf("protocols ospf area %s authentication plaintext-password", info.AreaId)
		} else if info.AuthType == MD5 {
			this.Tree.Setf("protocols ospf area %s authentication md5", info.AreaId)
		}
	}
	return nil;
}

func (this *ospfProtocol) setNetwork() error {
	if this.Tree == nil {
		return (fmt.Errorf("missing initial.."))
	}

	for _, info := range this.AreaInfos {
		if oldNetworks, ok := this.CurrentArea[info.AreaId]; ok {
			for _, on := range oldNetworks {
				deleted := true
				for _, n := range this.NetworkInfos {
					if n.Network == on {
						deleted = false
						break
					}
				}

				if deleted {
					this.Tree.Deletef("protocols ospf area %s network %s", info.AreaId, on)
				}
			}
		}

		for _, n := range this.NetworkInfos {
			if n.AreaId != info.AreaId {
				continue
			}
			/*
			ZSTAC-19018, modify network 192.168.48.1/24 to 192.168.48.0/24
			 */
			if _, cidr, err := net.ParseCIDR(n.Network); err != nil {
				return err
			} else {
				this.Tree.SetfWithoutCheckExisting("protocols ospf area %s network %s", info.AreaId, cidr.String())
			}
			nic, err := utils.GetNicNameByMac(n.NicMac)
			if err != nil {
				return err;
			}

			if !utils.IsSkipVyosIptables() {
				if r := this.Tree.FindFirewallRuleByDescription(nic, "local", FIREWALL_DESCRIPTION); r == nil {
					this.Tree.SetFirewallOnInterface(nic, "local",
						fmt.Sprintf("description %v", FIREWALL_DESCRIPTION),
						fmt.Sprintf("protocol ospf"),
						"action accept",
					)

				}
			}

			if info.AuthType == Plaintext {
				this.Tree.SetfWithoutCheckExisting("interfaces ethernet %s ip ospf authentication plaintext-password %s", nic, info.AuthParam)
			} else if info.AuthType == MD5 {
				pos := strings.IndexByte(info.AuthParam, '/')
				if pos < 0 {
					return fmt.Errorf("invalid authentication parametere:%s",info.AuthParam)
				}
				keyID, password := info.AuthParam[:pos], info.AuthParam[pos+1:]
				this.Tree.SetfWithoutCheckExisting("interfaces ethernet %s ip ospf authentication md5 key-id %s md5-key %s", nic, keyID, password)
			} else {
				this.Tree.SetfWithoutCheckExisting("interfaces ethernet %s ip ospf", nic)
			}

		}
	}

	for _, deletedNic := range this.ToBeDeletedOspfIntfs {
		this.Tree.Deletef("interfaces ethernet %s ip ospf", deletedNic)
		if r := this.Tree.FindFirewallRuleByDescription(deletedNic, "in", FIREWALL_DESCRIPTION); r != nil {
			r.Delete()
		}

		if r := this.Tree.FindFirewallRuleByDescription(deletedNic, "local", FIREWALL_DESCRIPTION); r != nil {
			r.Delete()
		}
	}

	return nil
}

func (this *ospfProtocol) setRawCmd(f string, args...interface{})  ( err error) {
	if this.Tree == nil {
		panic(fmt.Errorf("missing initial.."))
	}
	this.Tree.Setf(fmt.Sprintf(f, args...))
	return err
}

func (this *ospfProtocol) delRawCmd(f string, args...interface{})  ( err error) {
	if this.Tree == nil {
		panic(fmt.Errorf("missing initial.."))
	}
	this.Tree.Deletef(fmt.Sprintf(f, args...))

	return err
}

func (this *ospfProtocol) getNeighbors()  ( neighbors []neighbor,err error) {
	return neighbors,err
}

func (this *ospfProtocol) commit() (err error) {
	if this.Tree == nil {
		panic(fmt.Errorf("missing initial.."))
	}
	this.Tree.Apply(false)
	return nil
}

func getProtocol(id string, area []areaInfo, networks []networkInfo) protocol {
	if ip := net.ParseIP(id); ip == nil {
		panic(fmt.Errorf("router id[%s] is not formatted Ipv4 address.", id))
	}
	return &ospfProtocol{Id:id, AreaInfos:area, NetworkInfos:networks}
}

func refreshOspf(ctx *server.CommandContext) interface{} {
	/*
	1. if NetworkInfos null, deleteOspf else
	2. remove the whole ospf configure
	3. re-configure the ospf and commit
	 */
	cmd := &setOspfCmd{}
	ctx.GetCommand(cmd)

	log.Debugf(fmt.Sprintf("ospf refresh cmd for %v %v %v ", cmd.RouterId, cmd.AreaInfos, cmd.NetworkInfos))
	p := getProtocol(cmd.RouterId, cmd.AreaInfos, cmd.NetworkInfos);
	err := p.init(server.NewParserFromShowConfiguration().Tree); utils.PanicOnError(err)

	if cmd.NetworkInfos != nil && len(cmd.NetworkInfos) > 0 {
		err = p.setRouterId(); utils.PanicOnError(err)
		err = p.setArea(); utils.PanicOnError(err)
		err = p.setNetwork(); utils.PanicOnError(err)
		err = p.setRawCmd("protocols ospf log-adjacency-changes"); utils.PanicOnError(err)
	}

	p.commit()

	if utils.IsSkipVyosIptables() {
		syncOspfRulesByIptables(cmd.NetworkInfos)
	}

	return nil
}

func parseNeighbor(input string) ( []neighbor,  error) {
	neighbors := make([]neighbor,0,50)

	if input =="" {
		return neighbors, nil
	}
	rows := strings.Split(strings.Trim(input,"\\s+"), "\n")
	for _, row := range rows {
		if row == "" {
			continue
		}
		columns := strings.FieldsFunc(strings.Trim(row, "\\s+"), unicode.IsSpace)
		if len(columns) < 6 {
			log.Debugf(fmt.Sprintf("rows: %v row:%v columns:%v", rows, row, len(columns)))

			return nil, errors.Errorf("invalid neighbor string: %s", input)
		}

		neighbors = append(neighbors, neighbor{Id:columns[0], Priority:columns[1],State:columns[2],
				DeadTime:columns[3], NeighborAddress:columns[4], Device:columns[5]})
	}
	return neighbors, nil
}

/*testneighbors :=  []neighbor{
	neighbor{
		Id:"1.1.1.1",
		Priority:"5",
		State:"Full/DR",
		DeadTime:"40.88s",
		NeighborAddress:"192.168.251.244",
		Device:"eth2:192.168.251.12"},
	neighbor{
		Id:"1.1.2.1",
		Priority:"5",
		State:"Full/Backup",
		DeadTime:"40.88s",
		NeighborAddress:"192.168.252.244",
		Device:"eth2:192.168.252.18"},
}*/
func getNeighbors(ctx *server.CommandContext) interface{} {
	bash := utils.Bash {
		Command: fmt.Sprintf("vtysh -c 'show ip ospf neighbor' | tail -n +3; vtysh -c 'show ip ospf neighbor' >/dev/null"),
	}
	ret, o, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
	if ret != 0 {
		utils.PanicOnError(errors.Errorf(("get neighbor from zebra error")))
	}

	neighbors,err := parseNeighbor(o); utils.PanicOnError(err)

	return getOspfNeighborRsp{Neighbors:neighbors}
}

func syncOspfRulesByIptables(NetworkInfos []networkInfo) {
	table := utils.NewIpTables(utils.FirewallTable)
	
	ospfRules := utils.GetOSPFIpTableRule(table)
	table.RemoveIpTableRule(ospfRules)
	
	var filterRules []*utils.IpTableRule
	
	for _, info := range NetworkInfos {
		nicname, err := utils.GetNicNameByMac(info.NicMac);
		utils.PanicOnError(err)
		rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_OSPF)
		filterRules = append(filterRules, rule)
	}
	
	table.AddIpTableRules(filterRules)
	err := table.Apply(); utils.PanicOnError(err)
}

func OspfEntryPoint()  {
	server.RegisterAsyncCommandHandler(ROUTER_PROTOCOL_REFRESH_OSPF, server.VyosLock(refreshOspf))
	server.RegisterAsyncCommandHandler(ROUTER_PROTOCOL_GET_OSPF_NEIGHBOR, server.VyosLock(getNeighbors))
}