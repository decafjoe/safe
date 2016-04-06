.PHONY = check-update clean dist docs env help html lint pdf pristine test
COVERAGE = $(ENV)/bin/coverage
DIST = $(PWD)/dist/safe-$(shell $(PYTHON) setup.py --version).tar.gz
ENV = $(PWD)/.env
ENV_SOURCES = $(PWD)/setup.py $(PWD)/requirements.txt
FORCE_UPDATES_TO_PYTHON_PACKAGES = pip setuptools wheel
IGNORE_UPDATES_TO_PYTHON_PACKAGES = "\(safe\)\|\(virtualenv\)"
PIP = $(ENV)/bin/pip
PWD := $(shell pwd)
PYTHON = $(ENV)/bin/python
README = README.rst
SAFE = $(ENV)/bin/safe
SAFE_LINK = $(PWD)/bin/safe
SAFE_SOURCES = $(PWD)/src/safe.py
SPHINX = $(ENV)/bin/sphinx-build
VIRTUALENV ?= virtualenv


help :
	@printf "usage: make <target> where target is one of:\n\n"
	@printf "  check-update  Check for updates to packages\n"
	@printf "  clean         Delete generated files (dists, .pyc, etc)\n"
	@printf "  docs          Generate PDF and HTML documentation\n"
	@printf "  dist          Create sdist in dist/\n"
	@printf "  env           Install development environment\n"
	@printf "  html          Generate HTML documentation\n"
	@printf "  lint          Run linter on code\n"
	@printf "  pdf           Generate PDF documentation\n"
	@printf "  pristine      Delete development environment\n"
	@printf "  test          Run tests\n\n"


# =============================================================================
# ----- Environment -----------------------------------------------------------
# =============================================================================

$(PYTHON) :
	$(VIRTUALENV) --python=python2.7 $(ENV)

$(PIP) : $(PYTHON)

$(SAFE) : $(PIP) $(ENV_SOURCES)
	$(PIP) install -U $(FORCE_UPDATES_TO_PYTHON_PACKAGES)
	$(PIP) install \
		--editable . \
		--requirement requirements.txt
	touch $(SAFE)

$(SAFE_LINK) : $(SAFE)
	mkdir -p $(PWD)/bin
	ln -fs $(SAFE) $(SAFE_LINK)
	touch $(SAFE_LINK)

env : $(SAFE_LINK)

check-update : env
	@printf "Checking for library updates...\n"
	@$(PIP) list --outdated --local | \
		grep -v $(IGNORE_UPDATES_TO_PYTHON_PACKAGES) ||\
		printf "All libraries are up to date :)\n"

pristine : clean
	git clean -dfX


# =============================================================================
# ----- QA/Test ---------------------------------------------------------------
# =============================================================================

lint : env
	$(ENV)/bin/flake8 setup.py src
	@printf "Flake8 is happy :)\n"

test : lint
	$(COVERAGE) run setup.py test
	$(COVERAGE) report
	$(COVERAGE) html


# =============================================================================
# ----- Documentation ---------------------------------------------------------
# =============================================================================

html : env
	cd doc; make html SPHINXBUILD=$(SPHINX)

pdf : env
	cd doc; make latexpdf SPHINXBUILD=$(SPHINX)

docs: html pdf


# =============================================================================
# ----- Build -----------------------------------------------------------------
# =============================================================================

$(DIST) : $(README) $(SAFE_LINK) $(SAFE_SOURCES)
	cp $(README) README
	-$(PYTHON) setup.py sdist && touch $(DIST)
	rm README

dist : $(DIST)

clean :
	rm -rf \
		$(shell find . -type f -name .DS_Store) \
		$(shell find src -type f -name *.pyc) \
		.coverage \
		coverage \
		dist
