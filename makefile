ifndef GOROOT
    $(error GOROOT is not set)
endif

export GO=$(GOROOT)/bin/go
export GOPATH=$(shell pwd)

BUILD_DIR=build/out/zvr
TARGET_DIR=target/package/zvr
SOURCE_DIR=$(shell pwd)/src/zvr

.PHONY: all clean build package
all:
	$(MAKE) -C $(SOURCE_DIR)

build: all
	@mkdir -p $(BUILD_DIR)
	cp -f $(SOURCE_DIR)/zvr.out $(BUILD_DIR)/zvr

clean:
	$(MAKE) -C src/zvr/ clean
	$(RM) -r $(BUILD_DIR) $(TARGET_DIR)

package: build
	$(GO) run package.go -conf package-config.json
