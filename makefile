ifndef GOROOT
    $(error GOROOT is not set)
endif

export GO=$(GOROOT)/bin/go
export GOPATH=$(shell pwd)

BUILD_DIR=build/out/zvr
TARGET_DIR=target
SOURCE_DIR=$(shell pwd)/src/zvr

LIB_DIRS=$(shell cd src; ls -d zvr/*/; cd - > /dev/null)
DEPS=github.com/Sirupsen/logrus github.com/pkg/errors

build:
	mkdir -p $(TARGET_DIR)
	$(GO) build -o $(TARGET_DIR)/zvr zvr

deps:
	$(GO) get $(DEPS)

debug:
	echo $(LIB_DIRS)

clean:
	rm -rf target/

IDE:
	$(GO) install $(LIB_DIRS)
