# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import contextlib
import re

import sqlalchemy
import sqlalchemy.ext.declarative
import sqlalchemy.orm
import sqlalchemy.types


SLUG_RE = re.compile(r'^[a-zA-Z0-9_/-]{1,20}$')


def slug_error(value):
    if not SLUG_RE.search(value):
        return 'slugs must be 1-20 characters, composed of letters, ' \
            'underscores, hyphens, and forward slashes'


class Slug(sqlalchemy.types.TypeDecorator):
    impl = sqlalchemy.types.Unicode

    # TODO(jjoyce): figure out how to properly validate this type
    #               error is -- as implemented, this raises an
    #               exception on LIKE queries ('%thing%' does not
    #               match the regex)
    # def process_bind_param(self, value, _):
    #     assert SLUG_RE.search(value)
    #     return value


class ORM(object):
    IGNORED_MODELS = ['_sa_module_registry']

    def __init__(self):
        for module in (sqlalchemy, sqlalchemy.orm):
            for attr in module.__all__:
                if not hasattr(self, attr):
                    setattr(self, attr, getattr(module, attr))
        self.Model = sqlalchemy.ext.declarative.declarative_base()
        self.Slug = Slug

    @contextlib.contextmanager
    def bind(self, session):
        class QueryProperty(object):
            def __init__(self, session):
                self._session = session

            def __get__(self, _, type):
                mapper = sqlalchemy.orm.class_mapper(type)
                return sqlalchemy.orm.Query(mapper, session=self._session)

        self.Model.query = QueryProperty(session)
        try:
            yield
        finally:
            del self.Model.query
