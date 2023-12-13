GO_118_PATH := /usr/lib/golang1.18
ifneq ($(wildcard $(GO_118_PATH)),)
    GOROOT := $(GO_118_PATH)
endif

ifndef GOROOT
    $(error GOROOT is not set)
endif

GOROOT_LA ?= $(GOROOT)
GO_LA := $(GOROOT_LA)/bin/go


ARCH?=amd64 arm64

export GO=$(GOROOT)/bin/go
#export GOPATH=$(shell pwd)
export GOPROXY=https://goproxy.cn,direct
export GO111MODULE=on
SUPPORT_GO_WORKSPACE := $(shell $(GO) work help >/dev/null 2>&1 ; echo $$?)
ifneq ($(SUPPORT_GO_WORKSPACE), 0)
    $(error workspace mode is not supported, and requires go version greater than 1.18)
endif
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

DEPS=github.com/sirupsen/logrus github.com/pkg/errors github.com/fatih/structs github.com/prometheus/client_golang/prometheus github.com/bcicen/go-haproxy github.com/vishvananda/netlink

# for build version
VERSION=`cat data/file-lists/version`
GIT_INFO=`git name-rev --name-only HEAD | sed 's/remotes\/origin\///g'`/`git rev-parse HEAD`
USER=`git config user.email`
TIME=`TZ=Asia/Shanghai date +"%Y-%m-%d %H:%M:%S"`
PLATFORM=$${GOOS}/$${GOARCH}
GO_VERSION=`${GO} version | sed "s/go version //"`
LDFLAGS=-X 'zstack-vyos/utils.Version=${VERSION}' \
-X 'zstack-vyos/utils.GitInfo=${GIT_INFO}' \
-X 'zstack-vyos/utils.User=${USER}' \
-X 'zstack-vyos/utils.Time=${TIME}' \
-X 'zstack-vyos/utils.Platform=${PLATFORM}' \
-X 'zstack-vyos/utils.GoVersion=${GO_VERSION}'
PACKAGE_FLAG=-gitInfo "${GIT_INFO}" -user "${USER}" -time "${TIME}" -version "${VERSION}" -goVersion "${GO_VERSION}"

deps:
	$(GO) get $(DEPS)

clean:
	rm -rf target/

#package: clean zvr zvrarm zvrloong zvrboot zvrbootarm zvrbootloong
#package: clean zvr zvrarm zvrboot zvrbootarm
package: clean
	for arch in ${ARCH}; do \
		if [ $${arch} = amd64 ]; then \
			GOOS="linux" GOARCH="amd64"; $(GO) build -o $(TARGET_DIR)/zvr_x86_64 -ldflags="${LDFLAGS}" zvr/zvr.go; \
			GOOS="linux" GOARCH="amd64"; $(GO) build -o $(TARGET_DIR)/zvrboot_x86_64 -ldflags="${LDFLAGS}" zvrboot/zvrboot.go zvrboot/zvrboot_utils.go; fi; \
		if [ $${arch} = arm64 ]; then \
			CGO_ENABLED=0 GOOS="linux" GOARCH="arm64"; $(GO) build -o $(TARGET_DIR)/zvr_aarch64 -ldflags="${LDFLAGS}" zvr/zvr.go; \
			CGO_ENABLED=0 GOOS="linux" GOARCH="arm64"; $(GO) build -o $(TARGET_DIR)/zvrboot_aarch64 -ldflags="${LDFLAGS}" zvrboot/zvrboot.go zvrboot/zvrboot_utils.go; fi; \
		if [ $${arch} = loong64 ]; then \
			GOROOT=$(GOROOT_LA) CGO_ENABLED=0 GOOS="linux" GOARCH="loong64"; $(GO_LA) build -o $(TARGET_DIR)/zvr_loongarch64 -ldflags="${LDFLAGS}" zvr/zvr.go; \
			GOROOT=$(GOROOT_LA) GOOS="linux" GOARCH="loong64"; $(GO_LA) build -o $(TARGET_DIR)/zvrboot_loongarch64 -ldflags="${LDFLAGS}" zvrboot/zvrboot.go zvrboot/zvrboot_utils.go; fi; \
	done
	mkdir -p $(PKG_ZVR_DIR)
	mkdir -p $(PKG_ZVRBOOT_DIR)
	cp -f $(VERSION_FILE) $(TARGET_DIR)
	cp -a data/ $(PKG_ZVR_DIR)
	for arch in ${ARCH};do\
		if [ $${arch} = amd64 ]; then \
			cp -f $(TARGET_DIR)/zvr_x86_64 $(FILE_LIST_ZVR); \
			cp -f $(TARGET_DIR)/zvrboot_x86_64 $(PKG_ZVRBOOT_DIR); fi; \
		if [ $${arch} = arm64 ]; then \
			cp -f $(TARGET_DIR)/zvr_aarch64 $(FILE_LIST_ZVR); \
			cp -f $(TARGET_DIR)/zvrboot_aarch64 $(PKG_ZVRBOOT_DIR); fi; \
		if [ $${arch} = loong64 ]; then \
			cp -f $(TARGET_DIR)/zvr_loongarch64 $(FILE_LIST_ZVR); \
			cp -f $(TARGET_DIR)/zvrboot_loongarch64 $(PKG_ZVRBOOT_DIR); fi; \
	done
	cp -f scripts/grub.cfg.5.4.80 $(PKG_ZVR_DIR)
	cp -f scripts/grub.cfg.3.13 $(PKG_TAR_DIR)
	tar czf $(PKG_ZVR_DIR)/zvr-data.tar.gz -C $(DATA_ZVR_DIR) .
	rm -rf $(DATA_ZVR_DIR)
	$(GO) run package.go -conf package-config.json ${PACKAGE_FLAG} -platform "linux/(${ARCH})"

tar:
	rm -rf $(PKG_TAR_DIR)
	mkdir -p $(PKG_TAR_DIR)
	cp -a data/ $(PKG_TAR_DIR)
	for arch in ${ARCH}; do \
		if [ $${arch} = amd64 ]; then \
			cp -f $(TARGET_DIR)/zvr_x86_64 $(FILE_LIST_TAR); \
			cp -f $(TARGET_DIR)/zvrboot_x86_64 $(FILE_LIST_TAR); fi; \
		if [ $${arch} = arm64 ]; then \
			cp -f $(TARGET_DIR)/zvr_aarch64 $(FILE_LIST_TAR); \
			cp -f $(TARGET_DIR)/zvrboot_aarch64 $(FILE_LIST_TAR); fi; \
		if [ $${arch} = loong64 ]; then \
			cp -f $(TARGET_DIR)/zvr_loongarch64 $(FILE_LIST_TAR); \
			cp -f $(TARGET_DIR)/zvrboot_loongarch64 $(FILE_LIST_TAR); fi; \
	done
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