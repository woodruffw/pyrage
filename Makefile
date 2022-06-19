.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: env
env: env/pyvenv.cfg

env/pyvenv.cfg: dev-requirements.txt
	python -m venv env
	./env/bin/python -m pip install --upgrade pip
	./env/bin/python -m pip install --requirement dev-requirements.txt

.PHONY: develop
develop: env
	. ./env/bin/activate && maturin develop --extras=dev
	./env/bin/python -m pip install --editable ./pyrage-stubs

.PHONY: test
test: develop
	./env/bin/python -m unittest

.PHONY: dist
dist: dist-pyrage dist-pyrage-stubs

.PHONY: dist-pyrage
dist-pyrage: env
	docker run --rm -v $(shell pwd):/io konstin2/maturin build --release --strip --out dist

.PHONY: dist-pyrage-stubs
dist-pyrage-stubs: env
	./env/bin/python -m build ./pyrage-stubs --outdir dist
