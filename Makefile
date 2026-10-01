VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/kyoresuas/amnezia-fleet/internal/agent.Version=$(VERSION)
GOFLAGS := -trimpath
OUT := bin

.PHONY: all build agent probe fleetd vet fmt clean

all: vet build

build: fleetd agent probe

fleetd:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUT)/fleetd ./cmd/fleetd

# только Linux, для ARM: GOARCH=arm64
agent:
	CGO_ENABLED=0 GOOS=linux GOARCH=$${GOARCH:-amd64} go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUT)/fleet-agent ./cmd/fleet-agent

probe:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUT)/fleet-probe ./cmd/fleet-probe

vet:
	go vet ./...
	GOOS=linux go vet ./...

fmt:
	gofmt -w cmd internal

clean:
	rm -rf $(OUT)
