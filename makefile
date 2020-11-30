ifndef GOROOT
    $(error GOROOT is not set)
endif

export GO=$(GOROOT)/bin/go
export GOPATH=$(shell pwd)

TARGET_DIR=target
PKG_ZVR_DIR=$(TARGET_DIR)/pkg-zvr
PKG_ZVRBOOT_DIR=$(TARGET_DIR)/pkg-zvrboot
PKG_TAR_DIR=$(TARGET_DIR)/pkg-tar

DEPS=github.com/Sirupsen/logrus github.com/pkg/errors github.com/fatih/structs github.com/prometheus/client_golang/prometheus github.com/bcicen/go-haproxy

zvr:
	mkdir -p $(TARGET_DIR)
	$(GO) build -o $(TARGET_DIR)/zvr src/zvr/zvr.go

zvrboot:
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
	cp -f scripts/zvr_aarch64 $(PKG_ZVR_DIR)
	cp -f scripts/zstack-virtualrouteragent $(PKG_ZVR_DIR)
	cp -f scripts/haproxy $(PKG_ZVR_DIR)
	cp -f scripts/haproxy_aarch64 $(PKG_ZVR_DIR)
	cp -f scripts/gobetween $(PKG_ZVR_DIR)
	cp -f scripts/gobetween_aarch64 $(PKG_ZVR_DIR)
	cp -f scripts/keepalived $(PKG_ZVR_DIR)
	cp -f scripts/keepalived_aarch64 $(PKG_ZVR_DIR)
	cp -f scripts/healthcheck.sh $(PKG_ZVR_DIR)
	cp -f scripts/pimd $(PKG_ZVR_DIR)
	cp -f scripts/sshd.sh $(PKG_ZVR_DIR)
	cp -f scripts/sysctl.conf $(PKG_ZVR_DIR)
	cp -f scripts/zsn-crontab.sh $(PKG_ZVR_DIR)
	cp -f scripts/pimd_aarch64 $(PKG_ZVR_DIR)
	cp -f scripts/zvrboot_aarch64 $(PKG_ZVRBOOT_DIR)
	cp -f $(TARGET_DIR)/zvrboot $(PKG_ZVRBOOT_DIR)
	cp -f scripts/version $(TARGET_DIR)
	$(GO) run package.go -conf package-config.json

tar: zvr zvrboot
	rm -rf $(PKG_TAR_DIR)
	mkdir -p $(PKG_TAR_DIR)
	cp -f $(TARGET_DIR)/zvr $(PKG_TAR_DIR)
	cp -f scripts/zvr_aarch64 $(PKG_TAR_DIR)
	cp -f scripts/zvrboot_aarch64 $(PKG_TAR_DIR)
	cp -f scripts/haproxy $(PKG_TAR_DIR)
	cp -f scripts/haproxy_aarch64 $(PKG_TAR_DIR)
	cp -f scripts/gobetween $(PKG_TAR_DIR)
	cp -f scripts/gobetween_aarch64 $(PKG_TAR_DIR)
	cp -f scripts/keepalived $(PKG_TAR_DIR)
	cp -f scripts/keepalived_aarch64 $(PKG_TAR_DIR)
	cp -f scripts/healthcheck.sh $(PKG_TAR_DIR)
	cp -f scripts/zstack-virtualrouteragent $(PKG_TAR_DIR)
	cp -f scripts/version $(PKG_TAR_DIR)
	cp -f scripts/pimd $(PKG_TAR_DIR)
	cp -f scripts/sshd.sh $(PKG_TAR_DIR)
	cp -f scripts/sysctl.conf $(PKG_ZVR_DIR)
	cp -f scripts/zsn-crontab.sh $(PKG_TAR_DIR)
	cp -f scripts/pimd_aarch64 $(PKG_TAR_DIR)
	cp -f $(TARGET_DIR)/zvrboot $(PKG_TAR_DIR)
	tar czf $(TARGET_DIR)/zvr.tar.gz -C $(PKG_TAR_DIR) .

