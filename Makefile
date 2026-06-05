VENV := .venv
PYTHON := $(VENV)/bin/python
STAMP := $(VENV)/.installed
LANG ?= pt
ARGS ?=

.PHONY: run install dry-run clean help

run: install
	$(PYTHON) generate.py --lang $(LANG) $(ARGS)

dry-run: install
	$(PYTHON) generate.py --lang $(LANG) --dry-run $(ARGS)

install: $(STAMP)

$(STAMP): pyproject.toml
	uv venv $(VENV)
	uv sync
	touch $@

clean:
	rm -rf $(VENV) output/

help:
	@echo "make run [LANG=pt|es] [ARGS='--output path.pptx']"
	@echo "make dry-run [LANG=pt|es]   # print metrics, no .pptx"
	@echo "make install                # install deps only"
	@echo "make clean                  # remove venv and output/"
