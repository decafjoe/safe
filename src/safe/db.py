# -*- coding: utf-8 -*-
"""
Database helpers and ORM shim.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import contextlib

import sqlalchemy
import sqlalchemy.ext.declarative
import sqlalchemy.orm
import sqlalchemy.types


def open_database(path):
    """
    Return SQLAlchemy session for SQLite database at ``path``.

    :param str path: Path to SQLite file
    :return: SQLAlchemy session
    :rtype: :class:`sqlalchemy.orm.session.Session`
    """
    engine = sqlalchemy.create_engine('sqlite:///%s' % path)
    return sqlalchemy.orm.sessionmaker(bind=engine)()


class ORM(object):
    """Unified wrapper for SQLAlchemy's ORM API."""

    def __init__(self):
        """Initialize the wrapper."""
        for module in (sqlalchemy, sqlalchemy.orm):
            for attr in module.__all__:
                if not hasattr(self, attr):
                    setattr(self, attr, getattr(module, attr))
        self.Model = sqlalchemy.ext.declarative.declarative_base()

    @contextlib.contextmanager
    def bind(self, session):
        """
        Context manager to bind the ORM instance to a SQLAlchemy session.

        This adds a ``query`` convenience property to each model class,
        a la flask-sqlalchemy_.

        .. _flask-sqlalchemy: http://flask-sqlalchemy.pocoo.org/

        :param session: SQLAlchemy session to which to bind
        :type session: :class:`sqlalchemy.orm.session.Session`
        """
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
