VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build build-rpi build-lab test vet fmt

all: vet test build-rpi

# Бинарник для Raspberry Pi 5 (linux/arm64, статический).
build-rpi:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/routerd-linux-arm64 ./cmd/routerd

# Вспомогательные программы стенда (linux/arm64).
build-lab:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o bin/dohd-linux-arm64 ./testbed/dohd
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o bin/dhcpprobe-linux-arm64 ./testbed/dhcpprobe

# Бинарник для текущей платформы (CLI-команды работают и на macOS).
build:
	go build -ldflags '$(LDFLAGS)' -o bin/routerd ./cmd/routerd

test:
	go test ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l .; echo "gofmt: файлы выше не отформатированы"; exit 1)

fmt:
	gofmt -w .
