APP := auth-chaser
VERSION ?= 0.2.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build install test tidy run-check serve list-checks docker clean release

build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(APP) ./cmd/auth-chaser

install: build
	install -m 755 bin/$(APP) "$(HOME)/.local/bin/$(APP)"

test:
	go test ./...

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
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-amd64 ./cmd/auth-chaser
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-arm64 ./cmd/auth-chaser

clean:
	rm -rf bin dist .auth-chaser-data
