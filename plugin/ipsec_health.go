package plugin

import (
	prom "github.com/prometheus/client_golang/prometheus"
)

const (
	IPSEC_STATUS_NAME = "IPsec"
	IPSEC_STATE_UP    = "up"
	IPSEC_STATE_DOWN  = "down"
)

func init() {
	RegisterPrometheusCollector(NewIPSecPrometheusCollector())
}

type IPSecCollector struct {
	bytesEntry   *prom.Desc
	packetsEntry *prom.Desc
}

type IPSecStatistic struct {
	connName       string
	trafficBytes   int
	trafficPackets int
}

var (
	IpsecStateMap map[string]string
)

const (
	LABEL_IPSEC_UUID = "IPSecUuid"
)

func NewIPSecPrometheusCollector() MetricCollector {
	return &IPSecCollector{
		bytesEntry: prom.NewDesc(
			"zstack_ipsec_bytes",
			"IPSec connection traffic bytes",
			[]string{LABEL_IPSEC_UUID}, nil,
		),
		packetsEntry: prom.NewDesc(
			"zstack_ipsec_packets",
			"IPSec connection network packets",
			[]string{LABEL_IPSEC_UUID}, nil,
		),
	}
}
func (c *IPSecCollector) Describe(ch chan<- *prom.Desc) error {
	ch <- c.bytesEntry
	ch <- c.packetsEntry
	return nil
}

func (c *IPSecCollector) Update(ch chan<- prom.Metric) error {
	if !IsMaster() {
		return nil
	}

	for _, ipsecStatus := range getIpsecConnsStatistic() {
		ipsecUuid := ipsecStatus.connName
		ipsecBytes := ipsecStatus.trafficBytes
		ipsecPackets := ipsecStatus.trafficPackets
		ch <- prom.MustNewConstMetric(c.bytesEntry, prom.GaugeValue, float64(ipsecBytes), ipsecUuid)
		ch <- prom.MustNewConstMetric(c.packetsEntry, prom.GaugeValue, float64(ipsecPackets), ipsecUuid)
	}

	return nil
}
