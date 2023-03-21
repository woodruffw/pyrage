VENV = env
VENV_BIN = $(VENV)/bin

ifeq ($(OS), Windows_NT)
	VENV_BIN=$(VENV)/Scripts
endif


.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: env
env: env/pyvenv.cfg

$(VENV)/pyvenv.cfg: dev-requirements.txt
	python -m venv $(VENV)
	$(VENV_BIN)/python -m pip install --upgrade pip
	$(VENV_BIN)/python -m pip install --requirement dev-requirements.txt

.PHONY: develop
develop: env
	. $(VENV_BIN)/activate && maturin develop --extras=dev
	$(VENV_BIN)/python -m pip install --editable ./pyrage-stubs

.PHONY: test
test: develop
	$(VENV_BIN)/python -m unittest

.PHONY: dist
dist: dist-pyrage dist-pyrage-stubs

.PHONY: dist-pyrage
dist-pyrage: env
	docker run --rm -v $(shell pwd):/io ghcr.io/pyo3/maturin build --release --strip --out dist

.PHONY: dist-pyrage-stubs
dist-pyrage-stubs: env
	$(VENV_BIN)/python -m build ./pyrage-stubs --outdir dist
