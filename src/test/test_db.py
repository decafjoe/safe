# -*- coding: utf-8 -*-
"""
Tests for :mod:`safe.db`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import os

import sqlalchemy.orm.session

from safe.db import open_database, ORM
from safe.util import temporary_directory


def test_open_database():
    """Check that SQLite database can be opened successfully."""
    with temporary_directory() as tmp:
        path = os.path.join(tmp, 'test.db')
        db = open_database(path)
        assert isinstance(db, sqlalchemy.orm.session.Session)
        db.connection()  # checks that file can be "connected" to
        assert os.path.exists(path)


def test_wrapper():
    """Check that the ORM API wrapper has expected attributes."""
    orm = ORM()
    assert hasattr(orm, 'String')  # from sqlalchemy
    assert hasattr(orm, 'relationship')  # from sqlalchemy.orm


def test_bind():
    """Check that binding adds an appropriate ``query`` property to models."""
    orm = ORM()

    class Test(orm.Model):
        __tablename__ = 'test'
        id = orm.Column(orm.Integer, primary_key=True)

    with temporary_directory() as tmp:
        db = open_database(os.path.join(tmp, 'test.db'))
        assert not hasattr(Test, 'query')
        with orm.bind(db):
            assert hasattr(Test, 'query')
            assert isinstance(Test.query, sqlalchemy.orm.Query)
            assert Test.query.session is db
        assert not hasattr(Test, 'query')
