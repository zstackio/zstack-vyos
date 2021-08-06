package plugin

import (
        prom "github.com/prometheus/client_golang/prometheus"
        "net/http"
        glog "log"
        "fmt"
        "zvr/utils"
        "github.com/prometheus/client_golang/prometheus/promhttp"
        "zvr/server"
        log "github.com/Sirupsen/logrus"
)

const (
        PROMETHEUS_METRIC_PATH = "/metrics"
)


type MetricCollector interface {
        // Get new metrics and expose them via prometheus registry.
        Update(ch chan<- prom.Metric) error
        Describe(ch chan<- *prom.Desc) error
}

type prometheusServer struct {
        collectors []MetricCollector
}

var promServer = &prometheusServer{
        collectors: make([]MetricCollector, 0),
}

func (p *prometheusServer) Describe(ch chan <- *prom.Desc) {
        for _, cl := range p.collectors {
                err := cl.Describe(ch); utils.LogError(err)
        }
}

func (p *prometheusServer) Collect(ch chan <- prom.Metric) {
        for _, cl := range p.collectors {
                err := cl.Update(ch); utils.LogError(err)
        }
}

func RegisterPrometheusCollector(collector MetricCollector)  {
        promServer.collectors = append(promServer.collectors, collector)
}

type errorLogWriter struct{}

func (errorLogWriter) Write(b []byte) (int, error) {
        log.Error(string(b))
        return len(b), nil
}

func HandlePrometheusScrape(w http.ResponseWriter, r *http.Request) {
        reg := prom.NewRegistry()
        err := reg.Register(promServer); utils.LogError(err)
        if err != nil {
                w.WriteHeader(http.StatusInternalServerError)
                w.Write([]byte(fmt.Sprintf("Couldn't register collector: %s\n", err)))
                return
        }

        gatherers := prom.Gatherers{
 //               prom.DefaultGatherer,
                reg,
        }

        // Delegate http serving to Prometheus client library, which will call collector.Collect.
        h := promhttp.HandlerFor(gatherers,
                promhttp.HandlerOpts{
                        ErrorLog: glog.New(&errorLogWriter{}, "", 0),
                        ErrorHandling: promhttp.ContinueOnError,
                })
        h.ServeHTTP(w, r)
}

func PrometheusEntryPoint() {
        server.RegisterRawHttpHandler(PROMETHEUS_METRIC_PATH, HandlePrometheusScrape)
}