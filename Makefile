BINARY := prom-alert-lint
PKG := ./...

.PHONY: all build test race vet fmt fmtcheck lint smoke clean tidy

all: fmtcheck vet test build

build:
	go build -o $(BINARY) .

test:
	go test -count=1 $(PKG)

race:
	go test -race -count=1 $(PKG)

vet:
	go vet $(PKG)

fmt:
	gofmt -w .

fmtcheck:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

# Run the linter against the bundled examples.
smoke: build
	./$(BINARY) lint examples/good.yml
	@set +e; ./$(BINARY) lint examples/bad.yml; test $$? -eq 1 && echo "bad.yml failed as expected"

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
	rm -rf dist
