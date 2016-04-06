# -*- coding: utf-8 -*-
"""
test
====

Test helpers.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import contextlib
import os
import sys
import tempfile
import unittest

try:
    import cStringIO as StringIO
except ImportError:
    import StringIO

from safe import backend_map, safe as safe_app


@contextlib.contextmanager
def backend(*args):
    restore = dict()
    for name in backend_map.keys():
        if name not in args:
            restore[name] = backend_map[name]
            del backend_map[name]
    try:
        yield
    finally:
        for name, cls in restore.iteritems():
            backend_map[name] = cls


def safe(*argv):
    return_code = []

    def exit(code=0):
        return_code.append(code)

    orig_stdout, orig_stderr = sys.stdout, sys.stderr
    new_stdout, new_stderr = StringIO.StringIO(), StringIO.StringIO()
    sys.stdout, sys.stderr = new_stdout, new_stderr
    try:
        safe_app.main(('safe',) + argv, exit)
    finally:
        sys.stdout, sys.stderr = orig_stdout, orig_stderr
    return return_code[0], new_stdout.getvalue(), new_stderr.getvalue()


class TemporaryFileTestCase(unittest.TestCase):
    @contextlib.contextmanager
    def temporary_file(self, content):
        fd, fp = tempfile.mkstemp()
        try:
            f = os.fdopen(fd, 'w')
        except:
            os.close(fd)
            os.unlink(fp)
            raise
        try:
            f.write(content)
        except:
            f.close()
            os.unlink(fp)
            raise
        f.close()
        try:
            yield fp
        finally:
            os.unlink(fp)
