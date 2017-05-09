#
# Makefile for the safe project.
#
# Copyright Joe Joyce, 2016-2017. All rights reserved.
#

.PHONY = check-update clean dist docs env help html lint pdf pristine test

PROJECT = safe

# Virtualenv command
VIRTUALENV ?= virtualenv

# Base directories
PWD := $(shell pwd)
ENV = $(PWD)/.env

# Code
ENV_SOURCES = $(PWD)/setup.py $(PWD)/requirements.txt
README = $(PWD)/README.rst
SOURCES = $(PWD)/src/safe.py

# Commands
COVERAGE = $(ENV)/bin/coverage
FLAKE8 = $(ENV)/bin/flake8
PIP = $(ENV)/bin/pip
PYTHON = $(ENV)/bin/python
SAFE = $(ENV)/bin/safe
SAFE_LINK = $(PWD)/bin/safe
SPHINX = $(ENV)/bin/sphinx-build

# Distribution
VERSION = $(shell python setup.py --version)
DIST = $(PWD)/dist/$(PROJECT)-$(VERSION).tar.gz

# Python package settings
FORCE_UPDATES_TO_PYTHON_PACKAGES = pip setuptools wheel
IGNORE_UPDATES_TO_PYTHON_PACKAGES = "\(safe\)\|\(virtualenv\)"

# Git hooks
PRE_COMMIT = $(PWD)/.git/hooks/pre-commit
PRE_COMMIT_HOOK = make lint
PRE_PUSH = $(PWD)/.git/hooks/pre-push
PRE_PUSH_HOOK = make test


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
	@printf "  release       Cut a release of the software\n"
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
	ln -fs $(SAFE) $(SAFE_LINK)
	touch $(SAFE_LINK)

env : $(PRE_COMMIT) $(PRE_PUSH) $(SAFE_LINK)

check-update : env
	@printf "Checking for library updates...\n"
	@$(PIP) list --outdated --local --format=columns | \
		grep -v $(IGNORE_UPDATES_TO_PYTHON_PACKAGES) ||\
		printf "All libraries are up to date :)\n"

pristine : clean
	git clean -dfX


# =============================================================================
# ----- QA/Test ---------------------------------------------------------------
# =============================================================================

$(PRE_COMMIT) : $(PWD)/Makefile
	echo "$(PRE_COMMIT_HOOK)" > $(PRE_COMMIT)
	chmod +x $(PRE_COMMIT)

$(PRE_PUSH) : $(PWD)/Makefile
	echo "$(PRE_PUSH_HOOK)" > $(PRE_PUSH)
	chmod +x $(PRE_PUSH)

lint : env
	$(FLAKE8) \
		--ignore=D101,D102,D103,D203,D205,D400 \
		doc/conf.py setup.py src
	@printf "Flake8 is happy :)\n"

lint-pep257 : env
	$(FLAKE8) --ignore=D203 doc/conf.py setup.py src
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

$(DIST) : $(README) $(SAFE_LINK) $(SOURCES)
	cp $(README) README
	-$(PYTHON) setup.py sdist && touch $(DIST)
	rm README

dist : $(DIST)

release : dist
	$(PWD)/bin/make-release $(VERSION)
	make env

clean :
	rm -rf \
		$(shell find . -type f -name .DS_Store) \
		$(shell find src -type f -name *.pyc) \
		.coverage \
		coverage \
		dist
