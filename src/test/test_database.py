# -*- coding: utf-8 -*-
"""
test.test_database
==================

Tests :func:`safe.safe`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce, 2016-2017.
:license: Proprietary
"""
import datetime
import random
import time
import unittest

import arrow

from safe import Database, db, DEFAULT_NEW_SECRET_LENGTH, ModelMixin, Secret, \
    Sensitivity, Slug


class DatabaseTest(unittest.TestCase):
    def test_dump(self):
        db = Database()

        class Model(db.Model, ModelMixin):
            __tablename__ = 'test'
            value = db.Column(db.String(10), default='hello', nullable=False)

        db.initialize()
        db.session.add(Model())
        db.session.commit()

        data = db.dump()
        self.assertIn('Model', data)
        self.assertEqual(1, len(data['Model']))

        record = data['Model'][0]
        self.assertIn('id', record)
        self.assertEqual(1, record['id'])
        self.assertIn('created', record)
        self.assertTrue(isinstance(record['created'], datetime.datetime))
        self.assertIn('value', record)
        self.assertEqual(u'hello', record['value'])

    def test_load(self):
        def make_datetime():
            time.sleep(0.01)
            return arrow.utcnow().datetime

        s1_created = make_datetime()
        s1s1_created = make_datetime()
        s1s2_created = make_datetime()
        s1s3_created = make_datetime()
        s2_created = make_datetime()
        s2s1_created = make_datetime()
        s2s2_created = make_datetime()

        db.load(dict(
            Secret=(
                dict(id=100, created=s1_created, description='hello'),
                dict(id=200, created=s2_created, description='hola'),
            ),
            Slug=(
                dict(id=1, created=s1s1_created, slug='foo', secret_id=100),
                dict(id=2, created=s1s2_created, slug='bar', secret_id=100),
                dict(id=3, created=s1s3_created, slug='baz', secret_id=100),
                dict(id=4, created=s2s1_created, slug='qux', secret_id=200),
                dict(id=5, created=s2s2_created, slug='quux', secret_id=200),
            ),
        ))

        self.assertEqual(2, Secret.query.count())
        s1, s2 = Secret.query.order_by(Secret.created).all()

        def assert_secret(s, id, created, description, *slugs):
            slugs = map(unicode, slugs)
            self.assertEqual(id, s.id)
            self.assertEqual(created, s.created)
            self.assertTrue(s.active)
            self.assertTrue(s.autoupdate)
            self.assertEqual(description, s.description)
            self.assertEqual(0, s.email_query.count())
            self.assertEqual([], s.emails)
            self.assertEqual(u'', s.exclude)
            self.assertEqual(DEFAULT_NEW_SECRET_LENGTH, s.length)
            self.assertEqual(Sensitivity.DEFAULT, s.sensitivity)
            self.assertEqual(0, s.site_query.count())
            self.assertEqual([], s.sites)
            self.assertEqual(len(slugs), s.slug_query.count())
            query = s.slug_query.order_by(Slug.created)
            self.assertEqual(slugs, [ss.slug for ss in query.all()])
            self.assertEqual(slugs, [ss.slug for ss in s.slugs])

        assert_secret(s1, 1, s1_created, 'hello', 'foo', 'bar', 'baz')
        assert_secret(s2, 2, s2_created, 'hola', 'qux', 'quux')

        db.initialize()

    def test_cycle(self):
        db.initialize()
        db.load(db.dump())
        self.assertEqual(0, Secret.query.count())
        self.assertEqual(0, Slug.query.count())

        for _ in range(5):
            db.session.add(Secret())
        db.session.commit()
        for _ in range(10):
            secret = random.choice(Secret.query.all())
            db.session.add(Slug(secret_id=secret.id, slug=u'foo'))
        db.session.commit()

        db.load(db.dump())
        self.assertEqual(5, Secret.query.count())
        self.assertEqual(10, Slug.query.count())

        db.initialize()

    def test_models(self):
        db = Database()

        class Model(db.Model):
            __tablename__ = 'test'
            id = db.Column(db.Integer, primary_key=True)

        self.assertEqual(dict(Model=Model), db.models)

    def test_include_sqlalchemy_utils_respects_existing_attributes(self):
        arrow = object()
        Database.Arrow = arrow
        db = Database()
        self.assertIs(arrow, db.Arrow)
