.PHONY = clean dist env help lint pristine test
ENV = $(shell pwd)/.env
PROJECT = safe
VIRTUALENV ?= virtualenv


help :
	@printf "usage: make <target> where target is one of:\n\n"
	@printf "  clean     Delete generated files (dists, .pyc, etc)\n"
	@printf "  dist      Create sdist in dist/\n"
	@printf "  env       Install development environment\n"
	@printf "  pristine  Delete development environment\n"
	@printf "  test      Run tests\n\n"

$(ENV)/bin/$(PROJECT) : $(ENV)/bin/python
	$(ENV)/bin/pip install \
		--editable . \
		--requirement requirements.txt

$(ENV)/bin/python :
	$(VIRTUALENV) --python=python2.7 $(ENV)

bin/$(PROJECT) : $(ENV)/bin/$(PROJECT)
	mkdir -p bin
	ln -fs $(ENV)/bin/$(PROJECT) bin/$(PROJECT)

clean :
	rm -rf \
		$(shell find . -type f -name .DS_Store) \
		$(shell find src -type f -name *.pyc) \
		.coverage \
		coverage \
		dist

dist : env
	cp README.rst README
	-$(ENV)/bin/python setup.py sdist
	rm README

env : bin/$(PROJECT)

lint : env
	$(ENV)/bin/flake8 setup.py src
	@printf "Flake8 is happy :)\n"

pristine : clean
	git clean -dfX

test : lint
	$(ENV)/bin/coverage run setup.py test
	$(ENV)/bin/coverage report
	$(ENV)/bin/coverage html
