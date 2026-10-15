VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build build-rpi build-lab dist release test vet fmt

all: vet test build-rpi

# Бинарник для Raspberry Pi 5 (linux/arm64, статический).
build-rpi:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/routerd-linux-arm64 ./cmd/routerd

# Архив для установки на RPi: scp, tar -xzf, sudo ./install.sh.
DIST := routerd-$(VERSION)-linux-arm64
dist: build-rpi
	rm -rf dist/$(DIST) && mkdir -p dist/$(DIST)/bin
	cp -R install.sh README.md LICENSE deploy dist/$(DIST)/
	cp bin/routerd-linux-arm64 dist/$(DIST)/bin/
	COPYFILE_DISABLE=1 tar --format=ustar -C dist -czf dist/$(DIST).tar.gz $(DIST)
	rm -rf dist/$(DIST)
	@echo dist/$(DIST).tar.gz

# Релиз на GitHub (нужен gh): тег vX.Y.Z на коммите без изменений, версия
# совпадает с ansible/rpi5_gorouter/galaxy.yml и routerd_version в defaults
# роли. Роль Ansible скачивает архив и проверяет его по SHA256SUMS.
release: dist
	@case "$(VERSION)" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "нужен тег vX.Y.Z на HEAD без изменений (сейчас $(VERSION))"; exit 1;; esac
	@case "$(VERSION)" in *-*) echo "нужен тег vX.Y.Z на HEAD без изменений (сейчас $(VERSION))"; exit 1;; esac
	@grep -qx 'version: $(VERSION:v%=%)' ansible/rpi5_gorouter/galaxy.yml || \
		{ echo "ansible/rpi5_gorouter/galaxy.yml: версия не $(VERSION:v%=%)"; exit 1; }
	@grep -qx 'routerd_version: "$(VERSION:v%=%)"' ansible/rpi5_gorouter/roles/routerd/defaults/main.yml || \
		{ echo "defaults роли: routerd_version не $(VERSION:v%=%)"; exit 1; }
	cd dist && shasum -a 256 $(DIST).tar.gz >SHA256SUMS
	gh release create $(VERSION) dist/$(DIST).tar.gz dist/SHA256SUMS --title "routerd $(VERSION)" --notes "routerd $(VERSION): архив для install.sh и роли Ansible volkserg.rpi5_gorouter.routerd."

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
