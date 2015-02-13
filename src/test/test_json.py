"""
test.test_json
==============

Tests the datetime-enabled JSON functions.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
from datetime import datetime
from os.path import join
from shutil import rmtree
from tempfile import mkdtemp
from unittest import TestCase

from safe import dump_json, load_json


date = datetime(2014, 11, 11)
string = r'"\\/Date(1415682000000)\\/"'


class DecodeTest(TestCase):
    def test_dict_key(self):
        self.assertEqual({date: 'foo'}, load_json('{%s: "foo"}' % string))

    def test_dict_value(self):
        self.assertEqual(dict(foo=date), load_json('{"foo": %s}' % string))

    def test_list(self):
        self.assertEqual(['foo', date], load_json('["foo", %s]' % string))

    def test_nested_dict_key(self):
        json = '{"foo": {%s: "bar"}}' % string
        self.assertEqual(dict(foo={date: 'bar'}), load_json(json))

    def test_nested_dict_value(self):
        json = '{"foo": {"bar": %s}}' % string
        self.assertEqual(dict(foo=dict(bar=date)), load_json(json))

    def test_nested_list(self):
        json = '["foo", ["bar", %s]]' % string
        self.assertEqual(['foo', ['bar', date]], load_json(json))

    def test_number(self):
        self.assertEqual(1, load_json('1'))

    def test_solo(self):
        self.assertEqual(date, load_json(string))

    def test_string(self):
        self.assertEqual('foo', load_json('"foo"'))


class EncodeTest(TestCase):
    def test_date(self):
        self.assertEqual(string, dump_json(date))

    def test_non_date(self):
        self.assertRaises(TypeError, dump_json, 1j)


class WrapperTest(TestCase):
    def setUp(self):  # noqa
        self.tmp = mkdtemp()
        self.path = join(self.tmp, 'test.json')

    def tearDown(self):  # noqa
        rmtree(self.tmp)

    def test_dump(self):
        with open(self.path, 'w') as f:
            dump_json(1, f)
        with open(self.path) as f:
            self.assertEqual('1', f.read())

    def test_load(self):
        with open(self.path, 'w') as f:
            f.write('1')
        with open(self.path) as f:
            self.assertEqual(1, load_json(f))
