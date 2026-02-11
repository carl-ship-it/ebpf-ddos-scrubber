# Go Control Plane Build

BINARY     := ddos-scrubber
BUILD_DIR  := ../../build
GO         := go
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS    := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

PROTO_DIR  := api/proto
PROTO_OUT  := api/gen

.PHONY: all build clean proto test lint run

all: build

# Build the binary
build:
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/scrubber

# Generate protobuf Go code
proto:
	@mkdir -p $(PROTO_OUT)
	protoc \
		--go_out=$(PROTO_OUT) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_OUT) --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/scrubber.proto

# Run tests
test:
	$(GO) test -v -race ./...

# Run linter
lint:
	golangci-lint run ./...

# Run with default config
run: build
	sudo $(BUILD_DIR)/$(BINARY) \
		-config ../../configs/config.yaml \
		-log-level debug

# Download dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Clean
clean:
	rm -f $(BUILD_DIR)/$(BINARY)

# Install development tools
install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
