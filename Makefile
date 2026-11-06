GO ?= go
export GOMAXPROCS ?= 2
export GOMEMLIMIT ?= 1200MiB
export GOTMPDIR := $(CURDIR)/.cache/go-tmp
.PHONY: build test race vet
build:
	AGENTSSH_GO=$(GO) bash scripts/build.sh
test:
	mkdir -p $(GOTMPDIR)
	$(GO) test -p 2 ./...
race:
	mkdir -p $(GOTMPDIR)
	$(GO) test -race -p 1 ./...
vet:
	$(GO) vet ./...
