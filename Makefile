UV ?= uv


.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: develop
develop:
	$(UV) sync --locked

.PHONY: test
test: develop
	$(UV) run --locked python -m unittest

.PHONY: dist
dist: dist-pyrage dist-pyrage-stubs

.PHONY: dist-pyrage
dist-pyrage:
	docker run --rm -v $(shell pwd):/io ghcr.io/pyo3/maturin build --release --sdist --strip --out dist

.PHONY: dist-pyrage-stubs
dist-pyrage-stubs:
	$(UV) build ./pyrage-stubs --out-dir dist
