VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X github.com/emmayusufu/tessera/internal/version.Version=$(VERSION)"

DOCKER_IMAGE ?= tessera
DOCKER_TAG ?= $(VERSION)

.PHONY: build test race vet fmt lint staticcheck clean

build:
	go build $(LDFLAGS) -o bin/coordinator ./cmd/coordinator
	go build $(LDFLAGS) -o bin/agent ./cmd/agent
	go build $(LDFLAGS) -o bin/tessera ./cmd/tessera

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .
	goimports -w .

staticcheck:
	staticcheck ./...

lint:
	golangci-lint run

clean:
	rm -rf bin
