BINARY := littlesnitch-analyser
PKG    := ./cmd/littlesnitch-analyser
BIN    := bin/$(BINARY)

VERSION ?= 0.1.0
TARBALL  = https://github.com/thorstenpfister/littlesnitch-analyser/archive/refs/tags/v$(VERSION).tar.gz
LDFLAGS  = -s -w -X main.version=$(VERSION)
FORMULA  = Formula/littlesnitch-analyser.rb

.PHONY: all build test vet fmt fmt-check tidy update-golden clean install release help

all: build

build: ## Build the binary into ./bin (override VERSION=x.y.z to bake in a version)
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o $(BIN) $(PKG)

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

release: ## Tag vVERSION, push it, rewrite the Formula sha256, commit and push (VERSION=x.y.z)
	@git diff --quiet HEAD || (echo "Working tree not clean" && exit 1)
	@test -f $(FORMULA) || (echo "$(FORMULA) missing" && exit 1)
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION)
	@echo "==> Computing tarball SHA256"
	@SHA=$$(curl -fsSL $(TARBALL) | shasum -a 256 | awk '{print $$1}'); \
	  test -n "$$SHA" || (echo "Failed to fetch tarball" && exit 1); \
	  sed -i.bak -E \
	    -e 's|url "https://github.com/thorstenpfister/littlesnitch-analyser/archive/refs/tags/v[^"]+\.tar\.gz"|url "$(TARBALL)"|' \
	    -e "s|sha256 \"[a-f0-9]*\"|sha256 \"$$SHA\"|" \
	    $(FORMULA); \
	  rm $(FORMULA).bak; \
	  echo "Formula updated to v$(VERSION) (sha256 $$SHA)"
	git add $(FORMULA)
	git commit -m "Bump formula to v$(VERSION)"
	git push

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
