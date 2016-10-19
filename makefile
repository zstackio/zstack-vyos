ifndef GOROOT
    $(error GOROOT is not set)
endif

export GO=$(GOROOT)/bin/go
export GOPATH=$(shell pwd)

TARGET_DIR=target
PKG_DIR=$(TARGET_DIR)/package

DEPS=github.com/Sirupsen/logrus github.com/pkg/errors

build: deps
	mkdir -p $(TARGET_DIR)
	$(GO) build -o $(TARGET_DIR)/zvr zvr

deps:
	$(GO) get $(DEPS)

clean:
	rm -rf target/

package: clean build
	mkdir -p $(PKG_DIR)
	cp -f $(TARGET_DIR)/zvr $(PKG_DIR)
	cp -f scripts/zstack-virtualrouteragent $(PKG_DIR)
	$(GO) run package.go -conf package-config.json
