APP := auth-chaser
MODULE := github.com/Romstar/auth-chaser
VERSION ?= 0.1.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build install test tidy run-check serve docker clean

build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(APP) ./cmd/auth-chaser

install: build
	install -m 755 bin/$(APP) "$(HOME)/.local/bin/$(APP)"

test:
	go test ./...

tidy:
	go mod tidy

run-check: build
	./bin/$(APP) check --help

serve: build
	./bin/$(APP) serve --addr :8080

docker:
	docker build -t $(APP):$(VERSION) .

clean:
	rm -rf bin
