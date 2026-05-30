BINARY := littlesnitch-analyser
PKG    := ./cmd/littlesnitch-analyser
BIN    := bin/$(BINARY)

.PHONY: all build test vet fmt fmt-check tidy update-golden clean install help

all: build

build: ## Build the binary into ./bin
	@mkdir -p bin
	go build -o $(BIN) $(PKG)

test: ## Run unit + golden tests
	go test ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format all Go sources in place
	gofmt -w .

fmt-check: ## Fail if any Go file is not gofmt-clean
	@files=$$(gofmt -l .); if [ -n "$$files" ]; then printf 'gofmt needed:\n%s\n' "$$files"; exit 1; fi

tidy: ## Tidy go.mod/go.sum
	go mod tidy

update-golden: ## Regenerate golden fixtures after intended output changes
	go test ./cmd/... -update

install: ## Install the binary into $GOBIN (or $GOPATH/bin)
	go install $(PKG)

clean: ## Remove build artifacts
	rm -rf bin

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
