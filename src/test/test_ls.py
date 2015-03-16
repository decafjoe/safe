"""
test.test_ls
============

Tests the ls command.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import os
import shutil
import tempfile
import unittest

from test import backend, safe


data = """[
  {
    "created": "\\\\/Date(1388552400000)\\\\/",
    "names": [
      "axe",
      "bbbb"
    ],
    "vals": {
      "\\\\/Date(1388552400000)\\\\/": "qux"
    }
  },
  {
    "created": "\\\\/Date(1370059200000)\\\\/",
    "names": [
      "bar"
    ],
    "vals": {
      "\\\\/Date(1370059200000)\\\\/": "garply"
    }
  },
  {
    "created": "\\\\/Date(1357016400000)\\\\/",
    "names": [
      "baz",
      "aaaa"
    ],
    "vals": {
      "\\\\/Date(1357016400000)\\\\/": "quux",
      "\\\\/Date(1372651200000)\\\\/": "flux"
    }
  }
]
"""


class LsTest(unittest.TestCase):
    def _assert_output(self, args, lines):
        with backend('plaintext'):
            rv, stdout, stderr = safe('-f', self.path, 'ls', *args)
        self.assertEqual(0, rv)
        self.assertSequenceEqual(lines + ('',), stdout.split('\n'))
        self.assertEqual('', stderr)

    def assert_ls(self, *args):
        self._assert_output(args[:-1], args[-1])
        self._assert_output(args[:-1] + ('-r',), tuple(reversed(args[-1])))

    def setUp(self):  # noqa
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, 'test')
        with open(self.path, 'w') as f:
            f.write(data)

    def tearDown(self):  # noqa
        shutil.rmtree(self.tmp)

    def test_empty(self):
        with backend('plaintext'):
            rv, stdout, stderr = safe('-f', 'does_not_exist', 'ls')
        self.assertEqual(0, rv)
        self.assertEqual('', stdout)
        self.assertEqual('', stderr)

    def test_sort_created(self):
        self.assert_ls('-s', 'created', (
            'baz  2013-01-01  2013-07-01  aaaa',
            'bar  2013-06-01  2013-06-01      ',
            'axe  2014-01-01  2014-01-01  bbbb',
        ))

    def test_sort_modified(self):
        self.assert_ls('-s', 'modified', (
            'bar  2013-06-01  2013-06-01      ',
            'baz  2013-01-01  2013-07-01  aaaa',
            'axe  2014-01-01  2014-01-01  bbbb',
        ))

    def test_sort_name_default(self):
        self.assert_ls((
            'axe  2014-01-01  2014-01-01  bbbb',
            'bar  2013-06-01  2013-06-01      ',
            'baz  2013-01-01  2013-07-01  aaaa',
        ))

    def test_sort_name_explicit(self):
        self.assert_ls('-s', 'name', (
            'axe  2014-01-01  2014-01-01  bbbb',
            'bar  2013-06-01  2013-06-01      ',
            'baz  2013-01-01  2013-07-01  aaaa',
        ))
