ifndef GOROOT
    $(error GOROOT is not set)
endif

export GO=$(GOROOT)/bin/go
export GOPATH=$(shell pwd)

TARGET_DIR=target
PKG_ZVR_DIR=$(TARGET_DIR)/pkg-zvr
PKG_ZVRBOOT_DIR=$(TARGET_DIR)/pkg-zvrboot
PKG_APVM_DIR=$(TARGET_DIR)/pkg-apvm
PKG_TAR_DIR=$(TARGET_DIR)/pkg-tar

DEPS=github.com/Sirupsen/logrus github.com/pkg/errors

zvr: deps
	mkdir -p $(TARGET_DIR)
	$(GO) build -o $(TARGET_DIR)/zvr src/zvr/zvr.go src/zvr/option.go

zvrboot: deps
	mkdir -p $(TARGET_DIR)
	$(GO) build -o $(TARGET_DIR)/zvrboot src/zvr/zvrboot.go

apvm: deps
	mkdir -p $(TARGET_DIR)
	$(GO) build -o $(TARGET_DIR)/apvm src/zvr/appliancevm.go src/zvr/option.go

deps:
	$(GO) get $(DEPS)

clean:
	rm -rf target/

package: clean zvr zvrboot apvm
	mkdir -p $(PKG_ZVR_DIR)
	mkdir -p $(PKG_ZVRBOOT_DIR)
	mkdir -p $(PKG_APVM_DIR)
	cp -f $(TARGET_DIR)/zvr $(PKG_ZVR_DIR)
	cp -f scripts/zstack-virtualrouteragent $(PKG_ZVR_DIR)
	cp -f $(TARGET_DIR)/zvrboot $(PKG_ZVRBOOT_DIR)
	cp -f $(TARGET_DIR)/apvm $(PKG_APVM_DIR)
	cp -f scripts/zstack-appliancevm $(PKG_APVM_DIR)
	$(GO) run package.go -conf package-config.json

tar: zvr zvrboot
	rm -rf $(PKG_TAR_DIR)
	mkdir -p $(PKG_TAR_DIR)
	cp -f $(TARGET_DIR)/zvr $(PKG_TAR_DIR)
	cp -f scripts/zstack-virtualrouteragent $(PKG_TAR_DIR)
	cp -f $(TARGET_DIR)/apvm $(PKG_TAR_DIR)
	cp -f scripts/zstack-appliancevm $(PKG_TAR_DIR)
	cp -f $(TARGET_DIR)/zvrboot $(PKG_TAR_DIR)
	tar czf $(TARGET_DIR)/zvr.tar.gz -C $(PKG_TAR_DIR) .

