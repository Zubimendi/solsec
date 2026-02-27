.PHONY: all build test lint clean install sec

BINARY    := solsec
BUILD_DIR := dist
VERSION   := $(shell git describe --tags --always 2>/dev/null || echo "dev")
LDFLAGS   := -ldflags="-s -w -X main.version=$(VERSION)"

all: test build

build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) .
	@echo "✅ Built: $(BUILD_DIR)/$(BINARY)"

install:
	go install $(LDFLAGS) .

test:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run ./...

sec:
	gosec ./...
	govulncheck ./...

coverage: test
	go tool cover -html=coverage.out

release:
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64   .
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64  .
	GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe .

clean:
	rm -rf $(BUILD_DIR) coverage.out