.PHONY: all
all: proto generate

.PHONY: generate
generate:
	go generate ./...

.PHONY: proto
proto:
	buf generate .
