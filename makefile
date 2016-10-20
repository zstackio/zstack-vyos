ifndef GOROOT
    $(error GOROOT is not set)
endif

export GO=$(GOROOT)/bin/go
export GOPATH=$(shell pwd)

TARGET_DIR=target
PKG_DIR=$(TARGET_DIR)/package

DEPS=github.com/Sirupsen/logrus github.com/pkg/errors

zvr: deps
	mkdir -p $(TARGET_DIR)
	$(GO) build -o $(TARGET_DIR)/zvr src/zvr/zvr.go

zvrboot: deps
	mkdir -p $(TARGET_DIR)
	$(GO) build -o $(TARGET_DIR)/zvrboot src/zvr/zvrboot.go

deps:
	$(GO) get $(DEPS)

clean:
	rm -rf target/

package: clean zvr zvrboot
	mkdir -p $(PKG_DIR)
	cp -f $(TARGET_DIR)/zvr $(PKG_DIR)
	cp -f scripts/zstack-virtualrouteragent $(PKG_DIR)
	$(GO) run package.go -conf package-config.json
