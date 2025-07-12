VERSION ?= $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || cat $(CURDIR)/.version 2> /dev/null || echo v0)
BLDVER = module:$(MODULE),version:$(VERSION),build:$(CIRCLE_BUILD_NUM)
BASE = $(CURDIR)
MODULE = luna

.PHONY: all $(MODULE) install
all: $(MODULE)

$(MODULE):| $(BASE)
	@GO111MODULE=on GOFLAGS=-mod=vendor CGO_ENABLED=0 go build -v -trimpath -o $(BASE)/bin/$@

$(BASE):
	@mkdir -p $(dir $@)

install:
	@GO111MODULE=on GOFLAGS=-mod=vendor CGO_ENABLED=0 go install -v
