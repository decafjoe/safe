"""
test.test_json
==============

Tests the datetime-enabled JSON functions.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import datetime
import os
import shutil
import tempfile
import unittest

import mock

from safe import dump_json, load_json


date = datetime.datetime(2014, 11, 11)
string = r'"\\/Date(1415682000000)\\/"'


class DecodeTest(unittest.TestCase):
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


class EncodeTest(unittest.TestCase):
    def test_date(self):
        self.assertEqual(string, dump_json(date))

    def test_dictionary_date_key(self):
        self.assertEqual('{%s: "foo"}' % string, dump_json({date: 'foo'}))

    def test_list_with_dict_with_date_key(self):
        self.assertEqual('[{%s: "foo"}]' % string, dump_json([{date: 'foo'}]))

    def test_non_date(self):
        self.assertRaises(TypeError, dump_json, 1j)


class WrapperTest(unittest.TestCase):
    @mock.patch('os.fdopen')
    def test_dump_json_error(self, fdopen):
        fdopen.return_value = None
        path = os.path.join(tempfile.gettempdir(), 'test')
        self.assertRaises(AttributeError, dump_json, 1, path)

    def test_dump_fdopen_error(self):
        fd, fp = tempfile.mkstemp()
        os.close(fd)
        try:
            self.assertTrue(os.path.exists(fp))
            path = os.path.join(tempfile.gettempdir(), 'test')
            with mock.patch('tempfile.mkstemp') as mkstemp:
                mkstemp.return_value = fd, fp
                self.assertRaises(OSError, dump_json, 1, path)
            self.assertFalse(os.path.exists(fp))
        finally:
            if os.path.exists(fp):
                os.unlink(fp)

    def test_dump_to_file(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test.json')
            with open(path, 'w') as f:
                dump_json(1, f)
            with open(path) as f:
                self.assertEqual('1', f.read())
        finally:
            shutil.rmtree(tmp)

    def test_dump_to_path(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test.json')
            dump_json(1, path)
            with open(path) as f:
                self.assertEqual('1', f.read())
        finally:
            shutil.rmtree(tmp)

    def test_load(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test.json')
            with open(path, 'w') as f:
                f.write('1')
            with open(path) as f:
                self.assertEqual(1, load_json(f))
        finally:
            shutil.rmtree(tmp)
