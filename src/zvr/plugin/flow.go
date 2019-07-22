package plugin

import (
        "zvr/server"
        "zvr/utils"
        "fmt"
        log "github.com/Sirupsen/logrus"
        "github.com/pkg/errors"
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
        V5 	  FlowVersion = "V5"
        V9 	  FlowVersion = "V9"
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

type counter struct {
        Device string `json:"device"`
        TotalEntries string `json:"totalEntries"`
        TotalFlows string `json:"totalFlows"`
        TotalPkts string `json:"totalPkts"`
        TotalBytes string `json:"totalBytes"`
}

type getFlowCounterRsp struct {
        Counters []counter `json:"counters"`
}


func configFlowMeter(config flowMeterInfo) (error) {
        /*
       1. if NetworkInfos null, delete flowmeter else
       2. remove the whole flowmeter configure
       3. re-configure the flowmeter and commit
        */
	deleted := false
        tree := server.NewParserFromShowConfiguration().Tree
        if rs := tree.Getf("system flow-accounting"); rs != nil {
                tree.Deletef("system flow-accounting")
		deleted = true
        }

        if config.NetworkInfos != nil && len(config.NetworkInfos) > 0 {
                for _, n := range config.NetworkInfos {
                        nic, err := utils.GetNicNameByMac(n.NicMac); utils.PanicOnError(err)
                        tree.SetfWithoutCheckExisting("system flow-accounting interface %s", nic)
                }
        }

        if config.Type == NetFlow {
                if config.Collectors != nil && len(config.Collectors) > 0 {
                        for _, collector := range config.Collectors {
                                tree.SetfWithoutCheckExisting("system flow-accounting netflow server %s port %d", collector.Server, collector.Port)
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
                                tree.SetfWithoutCheckExisting("system flow-accounting sflow server %s port %d", collector.Server, collector.Port)
                        }
                }
                tree.Setf("system flow-accounting sflow sampling-rate %s", config.SampleRate)
                tree.Setf("system flow-accounting sflow agent-address %s", config.RouterId)
        }

        if rs := tree.Getf("system flow-accounting"); rs != nil || deleted {
                tree.Apply(false)
        }
        return nil
}


func refreshFlowMeter(ctx *server.CommandContext) interface{} {
        cmd := &setFlowMeterCmd{}
        ctx.GetCommand(cmd)

        log.Debugf(fmt.Sprintf("flowMeter refresh cmd for %v", cmd.FlowMeterInfo))
        err := configFlowMeter(cmd.FlowMeterInfo); utils.PanicOnError(err)

        return nil
}

/*input :=  []string{
	flow-accounting for [eth1]
        Total entries: 3
        Total flows  : 3
        Total pkts   : 9
        Total bytes  : 10,116
}*/
func parseCounter(input string) ( []counter,  error) {
        counters := make([]counter,0,30)

        if input =="" {
                return counters, nil
        }
        rows := strings.Split(strings.Trim(input,"\\s+"), "\n")
        if len(rows) < 5 {
                log.Debugf(fmt.Sprintf("invalid len:%d rows: %v", len(rows), rows))
                return counters, nil
        }

        var cut [5]string
        for idx := 0; idx <= len(rows)-len(cut); {
                if rows[idx] == "" {
                        idx = idx + 1
                        continue
                }
                for i := 0; i < len(cut); i=i+1 {
                        columns := strings.Split(strings.Trim(rows[idx+i], "\\s+"), " ")
                        cut[i] = columns[len(columns) - 1]
                }
                idx = idx + len(cut)

                counters = append(counters, counter{Device:cut[0],TotalEntries:cut[1],TotalFlows:cut[2],
                        TotalPkts:cut[3],TotalBytes:cut[4]})
        }
        return counters, nil
}

func getFlowCounter(ctx *server.CommandContext) interface{} {
        log.Debugf(fmt.Sprintf("start get flow counter: %v", ctx))
        bash := utils.Bash {
                Command: fmt.Sprintf("sudo /opt/vyatta/bin/sudo-users/vyatta-show-acct.pl -a show |egrep 'flow-accounting|Total' 2>/dev/null"),
        }
        ret, o, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
        if ret != 0 {
                utils.PanicOnError(errors.Errorf(("get counter from zebra error")))
        }

        counters,err := parseCounter(o); utils.PanicOnError(err)
        log.Debugf(fmt.Sprintf("end get flow counter: %v", counters))
        return getFlowCounterRsp{Counters:counters}
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
-A VYATTA_CT_TIMEOUT -j RETURN`

        bash := utils.Bash {
                Command: "sudo iptables -t raw -C  PREROUTING -j VYATTA_CT_PREROUTING_HOOK",
        }
        ret, o, _, err := bash.RunWithReturn(); utils.PanicOnError(err)
        log.Debugf(fmt.Sprintf("iptables raw output: %v ", o))
        if ret != 0 {
                ruleset := strings.Split(rules, "\n")
                err := utils.AppendIptalbesRuleSet(ruleset,"raw"); utils.PanicOnError(err)
        }
        return nil
}

func init() {
        makeEnv()
}

func FlowMeterEntryPoint()  {
        server.RegisterAsyncCommandHandler(FLOW_METER_REFRESH, server.VyosLock(refreshFlowMeter))
        server.RegisterAsyncCommandHandler(FLOW_METER_GET_COUNTER, server.VyosLock(getFlowCounter))
}
