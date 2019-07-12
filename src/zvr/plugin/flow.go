package plugin

import (
        "zvr/server"
        "zvr/utils"
        "fmt"
        log "github.com/Sirupsen/logrus"
        "strings"
)

const (
        FLOW_METER_REFRESH = "/flowmeter/refresh"
        FLOW_METER_GET_COUNTER = "/flowmeter/count"
)

type FlowType string
type FlowVersion string
const (
        NetFlow FlowType = "NetFlow"
        SFlow 	 FlowType = "sFlow"
)
const (
        V5 	  FlowVersion = "None"
        V9 	  FlowVersion = "MD5"
)

type interfaceInfo struct {
        NicMac string `json:"nicMac"`
        Network string `json:"network"`
}

type flowCollectorInfo struct {
        Server string `json:"server"`
        Port int `json:"port"`
}

type flowMeterInfo struct {
        SampleRate string `json:"sampleRate"`
        Collectors []flowCollectorInfo `json:"collectors"`
        NetworkInfos []interfaceInfo `json:"networkInfos"`
        Type FlowType `json:"type"`
        Ver FlowVersion `json:"version"`
        RouterId string `json:"routerId"`
        ExpireInterval int `json:"expireInterval"`
        ActiveTimeout int `json:"activeTimeout"`
}

type setFlowMeterCmd struct {
        FlowMeterInfo flowMeterInfo `json:"flowMeterInfor"`
}

type getFlowCounterRsp struct {

}


func configFlowMeter(config flowMeterInfo) (error) {
        /*
       1. if NetworkInfos null, deleteOspf else
       2. remove the whole ospf configure
       3. re-configure the ospf and commit
        */
        tree := server.NewParserFromShowConfiguration().Tree
        tree.Deletef("system flow-accounting")

        if config.NetworkInfos != nil && len(config.NetworkInfos) > 0 {
                for _, n := range config.NetworkInfos {
                        nic, err := utils.GetNicNameByMac(n.NicMac); utils.PanicOnError(err)
                        tree.Setf("system flow-accounting interface %s", nic)
                }
        }

        if config.Type == NetFlow {
                if config.Collectors != nil && len(config.Collectors) > 0 {
                        for _, collector := range config.Collectors {
                                tree.Setf("system flow-accounting netflow server %s port %d", collector.Server, collector.Port)
                        }
                }
                if config.Ver == V9 {
                        tree.Setf("system flow-accounting netflow version 9")
                } else {
                        tree.Setf("system flow-accounting netflow version 5")
                }
                tree.Setf("system flow-accounting netflow sampling-rate %s", config.SampleRate)
                tree.Setf("system flow-accounting netflow engine-id %s", config.RouterId)
                tree.Setf("system flow-accounting netflow timeout expiry-interval %d", config.ExpireInterval)
                tree.Setf("system flow-accounting netflow timeout max-active-life %d", config.ActiveTimeout)
        } else if config.Type == SFlow {
                if config.Collectors != nil && len(config.Collectors) > 0 {
                        for _, collector := range config.Collectors {
                                tree.Setf("system flow-accounting sflow server %s port %d", collector.Server, collector.Port)
                        }
                }
                tree.Setf("system flow-accounting sflow sampling-rate %s", config.SampleRate)
                tree.Setf("system flow-accounting sflow agent-address %s", config.RouterId)
        }


        tree.Apply(false)

        return nil
}


func refreshFlowMeter(ctx *server.CommandContext) interface{} {
        makeEnv()
        cmd := &setFlowMeterCmd{}
        ctx.GetCommand(cmd)

        log.Debugf(fmt.Sprintf("flowMeter refresh cmd for %v", cmd.FlowMeterInfo))
        err := configFlowMeter(cmd.FlowMeterInfo); utils.PanicOnError(err)

        return nil
}

/*test :=  []counter{
	Total entries: 406
        Total flows  : 483
        Total pkts   : 3,816
        Total bytes  : 330,391

}*/
func getFlowCounter(ctx *server.CommandContext) interface{} {
        return getFlowCounterRsp{}
}

func makeEnv() interface{} {
        rules := `-A PREROUTING -j VYATTA_CT_IGNORE
-A PREROUTING -j VYATTA_CT_TIMEOUT
-A PREROUTING -j VYATTA_CT_PREROUTING_HOOK
-A OUTPUT -j VYATTA_CT_IGNORE
-A OUTPUT -j VYATTA_CT_TIMEOUT
-A OUTPUT -j VYATTA_CT_OUTPUT_HOOK
-A VYATTA_CT_HELPER -j RETURN
-A VYATTA_CT_IGNORE -j RETURN
-A VYATTA_CT_OUTPUT_HOOK -j RETURN
-A VYATTA_CT_PREROUTING_HOOK -j RETURN
-A VYATTA_CT_TIMEOUT -j RETURN
-A PREROUTING -j VYATTA_CT_IGNORE
-A PREROUTING -j VYATTA_CT_TIMEOUT
-A PREROUTING -j VYATTA_CT_PREROUTING_HOOK`

        bash := utils.Bash {
                Command: "sudo iptables-save |grep \"\\-A PREROUTING -j VYATTA_CT_PREROUTING_HOOK\"",
        }
        ret, o, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
        log.Debugf(fmt.Sprintf("iptables raw output: %v ", o))
        if ret != 0 {
                ruleset := strings.Split(rules, "\n")
                err := utils.AppendIptalbesRuleSet(ruleset,"raw"); utils.PanicOnError(err)
        }
        return nil
}

func FlowMeterEntryPoint()  {
        server.RegisterAsyncCommandHandler(FLOW_METER_REFRESH, server.VyosLock(refreshFlowMeter))
        server.RegisterAsyncCommandHandler(FLOW_METER_GET_COUNTER, server.VyosLock(getFlowCounter))
}
