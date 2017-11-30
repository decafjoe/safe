# -*- coding: utf-8 -*-
"""
Tests for :mod:`safe`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import sqlalchemy
import sqlalchemy.orm

from clik import g
from clik.context import Context
from clik.util import AttributeDict

from safe.model import orm


def memory_db(fn):
    def decorate():
        engine = sqlalchemy.create_engine('sqlite://')
        metadata = orm.Model.metadata
        metadata.create_all(bind=engine, tables=metadata.tables.values())
        db = sqlalchemy.orm.sessionmaker(bind=engine)()
        ctx = Context()
        with ctx.acquire(g):
            with ctx(g=AttributeDict(db=db)), orm.bind(db):
                fn(db)
    return decorate
