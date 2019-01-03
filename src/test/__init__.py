# -*- coding: utf-8 -*-
"""
Tests for :mod:`safe`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2019.
:license: BSD
"""
import sqlalchemy
import sqlalchemy.orm
from clik import g
from clik.context import Context
from clik.util import AttributeDict

from safe.model import orm


def memory_db(fn):
    """
    Set up in-memory database for use with a test function.

    This creates and initializes the database, sets up ``g.db`` to reference
    the session, and binds the ORM to the session. When the test is complete
    the database is... well, simply forgotten and presumably GCed.
    """
    def decorate():
        engine = sqlalchemy.create_engine('sqlite://')
        metadata = orm.Model.metadata
        metadata.create_all(bind=engine, tables=metadata.tables.values())
        db = sqlalchemy.orm.sessionmaker(bind=engine)()
        ctx = Context()
        with ctx.acquire(g):
            with ctx(g=AttributeDict(db=db)), orm.bind(db):
                fn(db)

    # Set special attributes so Sphinx autodoc picks up the functions
    decorate.__module__ = fn.__module__
    decorate.__doc__ = fn.__doc__

    return decorate
