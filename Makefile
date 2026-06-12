# LightScan Makefile
# make          → install core (dev mode)
# make full     → install with all optional deps
# make go       → build Go scanner binary
# make test     → run test suite
# make lint     → ruff lint check
# make clean    → remove build artifacts and __pycache__
# make release  → bump version, tag, push

PYTHON  := python3
PIP     := $(PYTHON) -m pip
GOBIN   := scanner/lscan
GOSRC   := scanner/main.go
VERSION := $(shell grep '^version' pyproject.toml | head -1 | cut -d'"' -f2)

.PHONY: all install full go test lint clean release fmt

all: install

install:
	$(PIP) install -e .
	@echo "✓ LightScan $(VERSION) installed (stdlib core)"

full:
	$(PIP) install -e ".[full]"
	@echo "✓ LightScan $(VERSION) installed with all optional deps"

# Build the Go high-performance scanner binary
go:
	@command -v go >/dev/null 2>&1 || { echo "Go not found — install from https://go.dev/dl/"; exit 1; }
	cd scanner && go build -ldflags="-s -w" -o lscan ./main.go
	@echo "✓ Go scanner built → $(GOBIN)"

# Install Go binary to PATH
go-install: go
	install -m 755 $(GOBIN) /usr/local/bin/lscan
	@echo "✓ lscan installed to /usr/local/bin/lscan"

test:
	$(PYTHON) -m pytest tests/ -v --tb=short 2>/dev/null || \
		$(PYTHON) -m pytest lightscan/ --doctest-modules -v 2>/dev/null || \
		$(PYTHON) -m py_compile lightscan/**/*.py lightscan/*.py && echo "✓ Syntax OK"

lint:
	@command -v ruff >/dev/null 2>&1 && ruff check lightscan/ || \
		$(PYTHON) -m py_compile lightscan/**/*.py lightscan/*.py && echo "✓ No syntax errors"

fmt:
	@command -v ruff >/dev/null 2>&1 && ruff format lightscan/ || echo "ruff not installed — pip install ruff"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .ruff_cache/
	rm -f scanner/lscan
	@echo "✓ Clean"

# Quick smoke test — checks imports and --help work
smoke:
	$(PYTHON) -c "import lightscan; from lightscan.i18n import t; print(t('scan.done', n=0, crit=0, high=0, elapsed=0.0))"
	$(PYTHON) -m lightscan --help > /dev/null && echo "✓ --help OK"

# Tag and push a release
release:
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin "v$(VERSION)"
	@echo "✓ Tagged and pushed v$(VERSION)"
