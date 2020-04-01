TEST?=./...
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)

default: build

build:
	go install

test:
	go test $(TEST) -timeout=30s -parallel=4

fmt:
	@echo "==> Fixing source code with gofmt..."
	gofmt -s -w ./$(PKG_NAME)

.PHONY: build test fmt
