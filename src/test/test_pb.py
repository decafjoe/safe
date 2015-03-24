"""
test.test_copy
==============

Tests the pb command.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import argparse
import contextlib
import functools
import threading
import time
import unittest

import clik
import mock

from safe import pasteboard_drivers, get_pasteboard_driver, \
    pasteboard_driver, PasteboardDriver, PbcopyPasteboardDriver, \
    XclipPasteboardDriver

from test import backend, safe, TemporaryFileTestCase


# =============================================================================
# ----- Base ------------------------------------------------------------------
# =============================================================================

class PasteboardTestMixin(object):
    def context(self, pasteboard):
        return clik.context(args=argparse.Namespace(pasteboard=pasteboard))

    @contextlib.contextmanager
    def drivers(self, *args):
        pasteboard_drivers_orig = pasteboard_drivers[:]
        pasteboard_drivers[:] = args
        try:
            yield
        finally:
            pasteboard_drivers[:] = pasteboard_drivers_orig


class PasteboardDriverBaseTest(unittest.TestCase, PasteboardTestMixin):
    def test_class(self):
        cls = PasteboardDriver
        self.assertEqual(None, cls.add_arguments())
        self.assertRaises(NotImplementedError, cls.supports_platform)
        driver = cls()
        self.assertRaises(NotImplementedError, driver.read)
        self.assertRaises(NotImplementedError, driver.write, 'foo')

    def test_decorator(self):
        with self.drivers():
            self.assertEqual([], pasteboard_drivers)

            @pasteboard_driver
            class TestPasteboardDriver(PasteboardDriver):
                pass

            self.assertEqual([TestPasteboardDriver], pasteboard_drivers)


class GetPasteboardDriverTest(unittest.TestCase, PasteboardTestMixin):
    def make_driver(self, supports_platform, specificity_=0):
        class TestPasteboardDriver(PasteboardDriver):
            specificity = specificity_

            @staticmethod
            def supports_platform():
                return supports_platform
        return TestPasteboardDriver

    def test_multiple_by_name(self):
        class TestPasteboardDriverA(PasteboardDriver):
            specificity = 10

            @staticmethod
            def supports_platform():
                return True

        class TestPasteboardDriverB(PasteboardDriver):
            specificity = 10

            @staticmethod
            def supports_platform():
                return True

        with self.drivers(TestPasteboardDriverA, TestPasteboardDriverB):
            self.assertIs(get_pasteboard_driver(), TestPasteboardDriverA)

    def test_multiple_by_specificity(self):
        driver1 = self.make_driver(True, 10)
        driver2 = self.make_driver(True, 20)
        with self.drivers(driver1, driver2):
            self.assertIs(get_pasteboard_driver(), driver2)

    def test_none_at_all(self):
        with self.drivers():
            self.assertEqual(None, get_pasteboard_driver())

    def test_none_viable(self):
        driver1 = self.make_driver(False)
        driver2 = self.make_driver(False)
        with self.drivers(driver1, driver2):
            self.assertEqual(None, get_pasteboard_driver())

    def test_single(self):
        driver1 = self.make_driver(False)
        driver2 = self.make_driver(True)
        with self.drivers(driver1, driver2):
            self.assertIs(get_pasteboard_driver(), driver2)


# =============================================================================
# ----- Drivers ---------------------------------------------------------------
# =============================================================================

class PasteboardDriverTestMixin(PasteboardTestMixin):
    def assert_mock_read(self):
        driver = self.cls()
        process = mock.MagicMock()
        process.read.return_value = 'foo'
        with mock.patch('pexpect.spawn', side_effect=(process,)) as spawn:
            with self.context(pasteboard='bar'):
                self.assertEqual('foo', driver.read())
        self.assertIn('-%s bar' % self.selector, spawn.call_args[0][0])
        process.read.assert_called_once_with()
        process.close.assert_called_once_with()

    def assert_mock_write(self):
        driver = self.cls()
        process = mock.MagicMock()
        process.returncode = 42
        with mock.patch('subprocess.Popen', side_effect=(process,)) as popen:
            with self.context(pasteboard='foo'):
                self.assertEqual(42, driver.write('bar'))
        for arg in ('-%s' % self.selector, 'foo'):
            self.assertIn(arg, popen.call_args[0][0])
        process.communicate.assert_called_once_with('bar')
        process.wait.assert_called_once_with()

    def assert_pasteboard_argument(self):
        def true(): return True
        method = 'safe.%s.supports_platform' % self.cls.__name__
        with mock.patch(method, side_effect=true), self.drivers(self.cls):
            rv, stdout, stderr = safe('-fx', 'pb', '-h')
        self.assertEqual(rv, 0)
        self.assertIn('-p PASTEBOARD, --pasteboard PASTEBOARD', stdout)
        for choice in self.choices:
            self.assertIn(choice, stdout)
        self.assertEqual('', stderr)

    def test(self):
        self.assert_pasteboard_argument()
        self.assert_mock_read()
        self.assert_mock_write()


class PbcopyPasteboardDriverTest(unittest.TestCase, PasteboardDriverTestMixin):
    choices = ('find', 'font', 'general', 'ruler')
    cls = PbcopyPasteboardDriver
    selector = 'pboard'

    @unittest.skipUnless(PbcopyPasteboardDriver.supports_platform(), '')
    def test_real(self):
        driver = PbcopyPasteboardDriver()
        with self.context(pasteboard='general'):
            self.assertEqual(0, driver.write('foo'))
            self.assertEqual('foo', driver.read())


class XclipPasteboardDriverTest(unittest.TestCase, PasteboardDriverTestMixin):
    choices = ('clipboard', 'primary', 'secondary')
    cls = XclipPasteboardDriver
    selector = 'selection'

    @unittest.skipUnless(XclipPasteboardDriver.supports_platform(), '')
    def test_real(self):
        driver = XclipPasteboardDriver()
        with self.context(pasteboard='clipboard'):
            self.assertEqual(0, driver.write('foo'))
            self.assertEqual('foo', driver.read())


# =============================================================================
# ----- Command ---------------------------------------------------------------
# =============================================================================

class PbCommandTest(TemporaryFileTestCase, PasteboardTestMixin):
    def test_invalid_time(self):
        fn = functools.partial(safe, '-fx', 'pb', 'x', '-t')
        for t in ('-5', '0', '0.09999999'):
            rv, stdout, stderr = fn(t)
            self.assertEqual(61, rv)
            self.assertEqual('', stdout)
            msg = 'error: time must be >= 0.1: %s\n' % float(t)
            self.assertEqual(msg, stderr)

    def test_no_match(self):
        with backend('plaintext'), self.temporary_file('[]') as fp:
            rv, stdout, stderr = safe('-f', fp, 'pb', 'x')
        self.assertEqual(62, rv)
        self.assertEqual('', stdout)
        self.assertEqual('error: no secret with name: x\n', stderr)

    def test_put_failure(self):
        driver = get_pasteboard_driver()
        content = '[{"names": ["x"], "vals": {"a": "b"}}]'
        with backend('plaintext'), self.temporary_file(content) as fp:
            with mock.patch.object(driver, 'write', side_effect=(1, None, 1)):
                rv1, stdout1, stderr1 = safe('-f', fp, 'pb', 'x')
                rv2, stdout2, stderr2 = safe('-f', fp, 'pb', '-t', '0.1', 'x')

        self.assertEqual(63, rv1)
        self.assertEqual('', stdout1)
        msg = 'error: failed to copy secret to pasteboard\n'
        self.assertEqual(msg, stderr1)

        self.assertEqual(64, rv2)
        self.assertEqual('\r\rsecret on pasteboard for 0.1s...', stdout2)
        msg = 'error: failed to clear secret from the pasteboard\n'
        self.assertEqual(msg, stderr2)

    def test_success(self):
        driver = get_pasteboard_driver()()
        rvs = []
        values = []

        def run():
            rvs.append(safe('-f', fp, 'pb', '-t', '0.4', 'y'))

        content = '[{"names": ["x"]}, {"names": ["y"], "vals": {"a": "b"}}]'
        with backend('plaintext'), self.temporary_file(content) as fp:
            thread = threading.Thread(target=run)
            thread.start()
            time.sleep(0.2)
            values.append(driver.read())
            time.sleep(0.4)
            values.append(driver.read())

        thread.join()
        rv, stdout, stderr = rvs[0]
        self.assertEqual(0, rv)
        self.assertEqual(['b', 'x'], values)
        self.assertEqual('', stderr)

        expected_stdout = (
            '\r\r'
            'secret on pasteboard for 0.4s...'
            '\r                                \r'
            'secret on pasteboard for 0.3s...'
            '\r                                \r'
            'secret on pasteboard for 0.2s...'
            '\r                                \r'
            'secret on pasteboard for 0.1s...'
            '\r                                \r'
            'secret on pasteboard for 0.0s...'
            '\r                                \r'
            'pasteboard cleared\n'
        )
        self.assertEqual(expected_stdout, stdout)

    def test_unsupported(self):
        with self.drivers():
            rv, stdout, stderr = safe('-fx', 'pb', 'x')
        self.assertEqual(60, rv)
        self.assertEqual('', stdout)
        msg = 'error: no pasteboard support for your platform\n'
        self.assertEqual(msg, stderr)
