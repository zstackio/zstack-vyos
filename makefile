ifndef GOROOT
    $(error GOROOT is not set)
endif

export GO=$(GOROOT)/bin/go
export GOPATH=$(shell pwd)

TARGET_DIR=target
PKG_ZVR_DIR=$(TARGET_DIR)/pkg-zvr
PKG_ZVRBOOT_DIR=$(TARGET_DIR)/pkg-zvrboot

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
	mkdir -p $(PKG_ZVR_DIR)
	mkdir -p $(PKG_ZVRBOOT_DIR)
	cp -f $(TARGET_DIR)/zvr $(PKG_ZVR_DIR)
	cp -f scripts/zstack-virtualrouteragent $(PKG_ZVR_DIR)
	cp -f $(TARGET_DIR)/zvrboot $(PKG_ZVRBOOT_DIR)
	$(GO) run package.go -conf package-config.json
