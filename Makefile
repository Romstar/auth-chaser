APP := auth-chaser
VERSION ?= 0.2.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
# Pure Go static binary: no libc/CGO dependency (sqlite driver is modernc.org/sqlite).
CGO_ENABLED ?= 0
export CGO_ENABLED
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
GO_BUILD := go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: build install test tidy run-check serve list-checks docker clean release package website website-dev

build:
	mkdir -p bin
	$(GO_BUILD) -o bin/$(APP) ./cmd/auth-chaser

install: build
	install -m 755 bin/$(APP) "$(HOME)/.local/bin/$(APP)"

test:
	CGO_ENABLED=0 go test ./...

tidy:
	go mod tidy

list-checks: build
	./bin/$(APP) list-checks

run-check: build
	./bin/$(APP) check --help

serve: build
	./bin/$(APP) serve --addr :8080

docker:
	docker build -t $(APP):$(VERSION) .

release:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO_BUILD) -o dist/$(APP)-linux-amd64 ./cmd/auth-chaser
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO_BUILD) -o dist/$(APP)-linux-arm64 ./cmd/auth-chaser

package:
	chmod +x scripts/package.sh packaging/scripts/postinstall.sh
	VERSION=$(VERSION) COMMIT=$(COMMIT) ./scripts/package.sh

website:
	cd website && npm install && npm run build

website-dev:
	cd website && npm install && npm run dev

clean:
	rm -rf bin dist .auth-chaser-data website/out website/.next
