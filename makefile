ifndef GOROOT
    $(error GOROOT is not set)
endif

export GO=$(GOROOT)/bin/go
#export GOPATH=$(shell pwd)
export GO111MODULE=on
export TestEnv=devTestEnv.json

TARGET_DIR=target
PKG_ZVR_DIR=$(TARGET_DIR)/pkg-zvr
PKG_ZVRBOOT_DIR=$(TARGET_DIR)/pkg-zvrboot
PKG_TAR_DIR=$(TARGET_DIR)/pkg-tar

DEPS=github.com/Sirupsen/logrus github.com/pkg/errors github.com/fatih/structs github.com/prometheus/client_golang/prometheus github.com/bcicen/go-haproxy

.PHONY: zvr
zvr:
	mkdir -p $(TARGET_DIR)
	$(GO) build -mod vendor -o $(TARGET_DIR)/zvr zvr/zvr.go

.PHONY: zvrarm
zvrarm:
	mkdir -p $(TARGET_DIR)
	CGO_ENABLED=0 GOOS="linux" GOARCH="arm64" $(GO) build -mod vendor -o $(TARGET_DIR)/zvr_aarch64 zvr/zvr.go

.PHONY: zvrboot
zvrboot:
	mkdir -p $(TARGET_DIR)
	$(GO) build -mod vendor -o $(TARGET_DIR)/zvrboot zvrboot/zvrboot.go

.PHONY: zvrbootarm
zvrbootarm:
	mkdir -p $(TARGET_DIR)
	CGO_ENABLED=0 GOOS="linux" GOARCH="arm64" $(GO) build -mod vendor -o $(TARGET_DIR)/zvrboot_aarch64 zvrboot/zvrboot.go

deps:
	$(GO) get $(DEPS)

clean:
	rm -rf target/

package: clean zvr zvrarm zvrboot zvrbootarm
	mkdir -p $(PKG_ZVR_DIR)
	mkdir -p $(PKG_ZVRBOOT_DIR)
	cp -f $(TARGET_DIR)/zvr $(PKG_ZVR_DIR)
	cp -f $(TARGET_DIR)/zvr_aarch64 $(PKG_ZVR_DIR)
	cp -f scripts/ipsec.sh $(PKG_ZVR_DIR)
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
	cp -f scripts/rsyslog.sh $(PKG_ZVR_DIR)
	cp -f scripts/zvr-monitor.sh $(PKG_ZVR_DIR)
	cp -f scripts/file-monitor.sh $(PKG_ZVR_DIR)
	cp -f scripts/zvr-reboot.sh $(PKG_ZVR_DIR)
	cp -f scripts/cpu-monitor $(PKG_ZVR_DIR)
	cp -f scripts/sysctl.conf $(PKG_ZVR_DIR)
	cp -f scripts/conntrackd.conf $(PKG_ZVR_DIR)
	cp -f scripts/zsn-crontab.sh $(PKG_ZVR_DIR)
	cp -f scripts/pimd_aarch64 $(PKG_ZVR_DIR)
	cp -f scripts/uacctd $(PKG_ZVR_DIR)
	cp -f $(TARGET_DIR)/zvrboot $(PKG_ZVRBOOT_DIR)
	cp -f $(TARGET_DIR)/zvrboot_aarch64 $(PKG_ZVRBOOT_DIR)
	cp -f scripts/version $(TARGET_DIR)
	cp -f scripts/goprlimit $(PKG_ZVR_DIR)
	cp -f scripts/grub.cfg.5.4.80 $(PKG_ZVR_DIR)
	cp -f scripts/grub.cfg.3.13 $(PKG_TAR_DIR)
	$(GO) run -mod vendor package.go -conf package-config.json

tar: zvr zvrarm zvrboot zvrbootarm
	rm -rf $(PKG_TAR_DIR)
	mkdir -p $(PKG_TAR_DIR)
	cp -f $(TARGET_DIR)/zvr $(PKG_TAR_DIR)
	cp -f $(TARGET_DIR)/zvr_aarch64 $(PKG_ZVR_DIR)
	cp -f scripts/ipsec.sh $(PKG_TAR_DIR)
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
	cp -f scripts/uacctd $(PKG_TAR_DIR)
	cp -f scripts/sshd.sh $(PKG_TAR_DIR)
	cp -f scripts/rsyslog.sh $(PKG_TAR_DIR)
	cp -f scripts/zvr-monitor.sh $(PKG_TAR_DIR)
	cp -f scripts/file-monitor.sh $(PKG_TAR_DIR)
	cp -f scripts/zvr-reboot.sh $(PKG_TAR_DIR)
	cp -f scripts/cpu-monitor $(PKG_TAR_DIR)
	cp -f scripts/sysctl.conf $(PKG_TAR_DIR)
	cp -f scripts/conntrackd.conf $(PKG_TAR_DIR)
	cp -f scripts/zsn-crontab.sh $(PKG_TAR_DIR)
	cp -f scripts/pimd_aarch64 $(PKG_TAR_DIR)
	cp -f $(TARGET_DIR)/zvrboot $(PKG_TAR_DIR)
	cp -f $(TARGET_DIR)/zvrboot_aarch64 $(PKG_ZVRBOOT_DIR)
	cp -f scripts/goprlimit $(PKG_TAR_DIR)
	cp -f scripts/grub.cfg.5.4.80 $(PKG_TAR_DIR)
	cp -f scripts/grub.cfg.3.13 $(PKG_TAR_DIR)
	tar czf $(TARGET_DIR)/zvr.tar.gz -C $(PKG_TAR_DIR) .

.PHONY: test

test: clean package
	python=$$(which python3);\
	if [ $$? == 1 ];then\
		echo "can not find python3, please install python3";\
		exit 1;\
	fi;\
	pip install virtualenv;\
	virtualenv -p $$python newenv;\
	source newenv/bin/activate;\
	pip install -r test/requirements.txt;\
	python3 test/ut.py test/$(TestEnv)
