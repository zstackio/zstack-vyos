module github.com/zstackio/zstack-vyos

go 1.16

replace github.com/Sirupsen/logrus => github.com/sirupsen/logrus v1.2.1-0.20181103062819-44067abb194b

require (
	github.com/EvilSuperstars/go-cidrman v0.0.0-20190607145828-28e79e32899a
	github.com/Sirupsen/logrus v0.0.0-00010101000000-000000000000
	github.com/bcicen/go-haproxy v0.0.0-20180203142132-ff5824fe38be
	github.com/fatih/structs v1.1.1-0.20181010231757-878a968ab225
	github.com/gocarina/gocsv v0.0.0-20210516172204-ca9e8a8ddea8 // indirect
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/pkg/errors v0.8.1-0.20181023235946-059132a15dd0
	github.com/prometheus/client_golang v0.9.2
	github.com/sirupsen/logrus v1.8.1 // indirect
	golang.org/x/sys v0.0.0-20210423082822-04245dca01da
)
