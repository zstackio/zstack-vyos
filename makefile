GO_118_PATH := /usr/lib/golang1.18
GO_ROOT := $(shell \
    if [ -d "$(GO_118_PATH)" ]; then \
        echo "$(GO_118_PATH)"; \
    else \
        echo "$(GOROOT)"; \
    fi)

ifndef GO_ROOT
    $(error GOROOT is not set)
endif

export GOROOT=$(GO_ROOT)
export GO=$(GO_ROOT)/bin/go
#export GOPATH=$(shell pwd)
export GO111MODULE=on
export TestEnv=devTestEnv.json

TARGET_DIR=target
PKG_ZVR_DIR=$(TARGET_DIR)/pkg-zvr
PKG_ZVRBOOT_DIR=$(TARGET_DIR)/pkg-zvrboot
PKG_TAR_DIR=$(TARGET_DIR)/pkg-tar
DATA_ZVR_DIR=$(PKG_ZVR_DIR)/data
DATA_TAR_DIR=$(PKG_TAR_DIR)/data
FILE_LIST_ZVR=$(DATA_ZVR_DIR)/file-lists
FILE_LIST_TAR=$(DATA_TAR_DIR)/file-lists
VERSION_FILE=data/file-lists/version

DEPS=github.com/Sirupsen/logrus github.com/pkg/errors github.com/fatih/structs github.com/prometheus/client_golang/prometheus github.com/bcicen/go-haproxy github.com/vishvananda/netlink

.PHONY: zvr
zvr:
	mkdir -p $(TARGET_DIR)
	GOOS="linux" GOARCH="amd64" $(GO) build -mod vendor -o $(TARGET_DIR)/zvr_x86_64 zvr/zvr.go

.PHONY: zvrarm
zvrarm:
	mkdir -p $(TARGET_DIR)
	CGO_ENABLED=0 GOOS="linux" GOARCH="arm64" $(GO) build -mod vendor -o $(TARGET_DIR)/zvr_aarch64 zvr/zvr.go

.PHONY: zvrloong
zvrloong:
	mkdir -p $(TARGET_DIR)
	CGO_ENABLED=0 GOOS="linux" GOARCH="loong64" $(GO) build -mod vendor -o $(TARGET_DIR)/zvr_loongarch64 zvr/zvr.go

.PHONY: zvrboot
zvrboot:
	mkdir -p $(TARGET_DIR)
	GOOS="linux" GOARCH="amd64" $(GO) build -mod vendor -o $(TARGET_DIR)/zvrboot_x86_64 zvrboot/zvrboot.go zvrboot/zvrboot_utils.go

.PHONY: zvrbootarm
zvrbootarm:
	mkdir -p $(TARGET_DIR)
	CGO_ENABLED=0 GOOS="linux" GOARCH="arm64" $(GO) build -mod vendor -o $(TARGET_DIR)/zvrboot_aarch64 zvrboot/zvrboot.go zvrboot/zvrboot_utils.go

.PHONY: zvrbootloong
zvrbootloong:
	mkdir -p $(TARGET_DIR)
	GOOS="linux" GOARCH="loong64" $(GO) build -mod vendor -o $(TARGET_DIR)/zvrboot_loongarch64 zvrboot/zvrboot.go zvrboot/zvrboot_utils.go

deps:
	$(GO) get $(DEPS)

clean:
	rm -rf target/

#package: clean zvr zvrarm zvrloong zvrboot zvrbootarm zvrbootloong
package: clean zvr zvrarm zvrboot zvrbootarm
	mkdir -p $(PKG_ZVR_DIR)
	mkdir -p $(PKG_ZVRBOOT_DIR)
	cp -f $(VERSION_FILE) $(TARGET_DIR)
	cp -a data/ $(PKG_ZVR_DIR)
	cp -f $(TARGET_DIR)/zvr_x86_64 $(FILE_LIST_ZVR)
	cp -f $(TARGET_DIR)/zvr_aarch64 $(FILE_LIST_ZVR)
# 	cp -f $(TARGET_DIR)/zvr_loongarch64 $(FILE_LIST_ZVR)
	cp -f $(TARGET_DIR)/zvrboot_x86_64 $(PKG_ZVRBOOT_DIR)
	cp -f $(TARGET_DIR)/zvrboot_aarch64 $(PKG_ZVRBOOT_DIR)
# 	cp -f $(TARGET_DIR)/zvrboot_loongarch64 $(PKG_ZVRBOOT_DIR)
	cp -f zvr/zvr_loongarch64 $(FILE_LIST_ZVR)
	cp -f zvrboot/zvrboot_loongarch64 $(PKG_ZVRBOOT_DIR)
	cp -f scripts/grub.cfg.5.4.80 $(PKG_ZVR_DIR)
	cp -f scripts/grub.cfg.3.13 $(PKG_TAR_DIR)
	tar czf $(PKG_ZVR_DIR)/zvr-data.tar.gz -C $(DATA_ZVR_DIR) .
	rm -rf $(DATA_ZVR_DIR)
	$(GO) run -mod vendor package.go -conf package-config.json

tar: zvr zvrarm zvrboot zvrbootarm
	rm -rf $(PKG_TAR_DIR)
	mkdir -p $(PKG_TAR_DIR)
	cp -a data/ $(PKG_TAR_DIR)
	cp -f $(TARGET_DIR)/zvr_x86_64 $(FILE_LIST_TAR)
	cp -f $(TARGET_DIR)/zvr_aarch64 $(FILE_LIST_TAR)
# 	cp -f $(TARGET_DIR)/zvr_loongarch64 $(FILE_LIST_TAR)
	cp -f $(TARGET_DIR)/zvrboot_x86_64 $(FILE_LIST_TAR)
	cp -f $(TARGET_DIR)/zvrboot_aarch64 $(FILE_LIST_TAR)
# 	cp -f $(TARGET_DIR)/zvrboot_loongarch64 $(FILE_LIST_TAR)
	cp -f zvr/zvr_loongarch64 $(FILE_LIST_TAR)
	cp -f zvrboot/zvrboot_loongarch64 $(FILE_LIST_TAR)
	cp -f scripts/grub.cfg.5.4.80 $(PKG_TAR_DIR)
	cp -f scripts/grub.cfg.3.13 $(PKG_TAR_DIR)
	cp -f scripts/vyos-postconfig-bootup.script $(PKG_TAR_DIR)
	tar czf $(PKG_TAR_DIR)/zvr-data.tar.gz -C $(DATA_TAR_DIR) .
	rm -rf $(DATA_TAR_DIR)
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

.PHONY: unittest

unittest: clean package
	python=$$(which python3);\
	if [ $$? == 1 ];then\
		echo "can not find python3, please install python3";\
		exit 1;\
	fi;\
	if [ "$$focus" == "" ];then\
		echo "1 env variable is needed: focus='case name'";\
		exit 1;\
	fi;\
	if [ "$(shell find . -type f | grep /${focus}.go | grep -v ${fucus}.log | wc -l)" != 1 ];then\
		echo "Error: no/multiple cases were found through focus:${focus}";\
		exit 1;\
	fi;\
	pip install virtualenv;\
	virtualenv -p $$python newenv;\
	source newenv/bin/activate;\
	pip install -r test/requirements.txt;\
	python3 test/ut.py test/$(TestEnv) --case=$$focus