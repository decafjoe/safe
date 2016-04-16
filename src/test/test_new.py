# -*- coding: utf-8 -*-
"""
test.test_new
=============

Tests the new command.

:author: Joe Strickler <joe@decafjoe.com>
:copyright: Joe Strickler, 2016. All rights reserved.
:license: Proprietary
"""
import datetime
import unittest

from clik import context
from clik.util import AttributeDict
import mock

import safe as safe_module
from safe import get_pasteboard_driver, import_strategy, load_json, \
    GenerateImportStrategy, ImportStrategy, \
    InteractivelyGenerateImportStrategy, PasteboardImportStrategy, \
    PboardPasteboardDriver, PromptImportStrategy, \
    ImportStrategyFailedError, ImportStrategyNameConflictError

from test import backend, safe, TemporaryFileTestCase


# =============================================================================
# ----- Base ------------------------------------------------------------------
# =============================================================================

class ImportStrategyDecoratorTest(unittest.TestCase):
    def test(self):
        self.original_import_strategy_map = safe_module.import_strategy_map
        safe_module.import_strategy_map = dict()
        try:
            class TestImportStrategy(ImportStrategy):
                pass

            cls = import_strategy('test')(TestImportStrategy)
            self.assertIs(TestImportStrategy, cls)
            self.assertIn('test', safe_module.import_strategy_map)
            actual = safe_module.import_strategy_map['test']
            self.assertIs(TestImportStrategy, actual)
            exception = ImportStrategyNameConflictError
            self.assertRaises(exception, import_strategy, 'test')
        finally:
            safe_module.import_strategy_map = self.original_import_strategy_map


class ImportStrategyBaseTest(unittest.TestCase):
    def test(self):
        cls = ImportStrategy
        cls.add_arguments()
        self.assertRaises(NotImplementedError, cls.supports_platform)
        self.assertRaises(NotImplementedError, cls())


# =============================================================================
# ----- Import Strategy -------------------------------------------------------
# =============================================================================

class ImportStrategyTestCase(unittest.TestCase):
    def context(self, **kwargs):
        return context(args=AttributeDict(**kwargs))


class PasteboardImportStrategyTestCase(ImportStrategyTestCase):
    def context(self, **kwargs):
        if get_pasteboard_driver() is PboardPasteboardDriver:
            pasteboard = 'general'
        else:
            pasteboard = 'clipboard'
        kwargs.setdefault('pasteboard', pasteboard)
        return super(PasteboardImportStrategyTestCase, self).context(**kwargs)


class GenerateImportStrategyTest(ImportStrategyTestCase):
    def context(self, **kwargs):
        kwargs.setdefault('generate_length', 32)
        kwargs.setdefault('generate_without_charset', [])
        kwargs.setdefault('generate_without_chars', [])
        return super(GenerateImportStrategyTest, self).context(**kwargs)

    def test_characters(self):
        args = dict(
            generate_length=32,
            generate_without_chars='bcdefghijklmnopqrstuvwxyz',
            generate_without_charset=['digits', 'punctuation', 'uppercase'],
        )
        expected = 'a' * 32
        with self.context(**args):
            for _ in range(10):
                self.assertEqual(expected, GenerateImportStrategy()())

    def test_charset(self):
        charsets = ['lowercase', 'punctuation', 'uppercase']
        with self.context(generate_without_charset=charsets):
            for _ in range(10):
                self.assertTrue(GenerateImportStrategy()().isdigit())

    def test_empty_characters(self):
        charsets = ['digits', 'lowercase', 'punctuation', 'uppercase']
        strategy = GenerateImportStrategy()
        with self.context(generate_without_charset=charsets):
            self.assertRaises(ImportStrategyFailedError, strategy)

    def test_length(self):
        strategy = GenerateImportStrategy()
        with self.context(generate_length=32):
            self.assertEqual(32, len(strategy()))
            with self.context(generate_length=64):
                self.assertEqual(64, len(strategy()))


class InteractivelyGenerateImportStrategyTest(
        PasteboardImportStrategyTestCase,
):
    def context(self, **kwargs):
        kwargs.setdefault('interactive_length', 32)
        kwargs.setdefault('interactive_without_charset', [])
        kwargs.setdefault('interactive_without_chars', [])
        superclass = super(InteractivelyGenerateImportStrategyTest, self)
        return superclass.context(**kwargs)

    @mock.patch('safe.prompt_boolean', side_effect=(True,))
    def test_failure(self, _):
        calls = []

        def write(_):
            calls.append(None)
            if len(calls) > 1:
                return True

        pasteboard = get_pasteboard_driver()
        with mock.patch.object(pasteboard, 'write', side_effect=write):
            with self.context():
                exception = ImportStrategyFailedError
                strategy = InteractivelyGenerateImportStrategy()
                self.assertRaises(exception, strategy)

    def test_success(self):
        secrets = []
        pasteboard = get_pasteboard_driver()()

        def prompt_boolean(*args):
            self.assertEqual(1, len(args))
            secrets.append(pasteboard.read())
            return len(secrets) > 1

        with mock.patch('safe.prompt_boolean', side_effect=prompt_boolean):
            with self.context():
                InteractivelyGenerateImportStrategy()()
                self.assertEqual(2, len(secrets))
                self.assertNotEqual(*secrets)
                self.assertNotEqual(secrets[-1], pasteboard.read())


class PasteboardImportStrategyTest(PasteboardImportStrategyTestCase):
    def test(self):
        with self.context():
            get_pasteboard_driver()().write('foo')
            self.assertEqual('foo', PasteboardImportStrategy()())


class PromptImportStrategyTest(ImportStrategyTestCase):
    @mock.patch('getpass.getpass', side_effect=('a', 'b', 'foo', 'foo'))
    def test_default(self, getpass):
        with self.context(prompt_confirm=True):
            self.assertEqual('foo', PromptImportStrategy()())
            self.assertEqual(4, getpass.call_count)

    @mock.patch('getpass.getpass', side_effect=('foo',))
    def test_no_confirm(self, _):
        with self.context(prompt_confirm=False):
            self.assertEqual('foo', PromptImportStrategy()())


# =============================================================================
# ----- Command ---------------------------------------------------------------
# =============================================================================


class NewCommandTest(PasteboardImportStrategyTestCase, TemporaryFileTestCase):
    def setUp(self):  # noqa
        pasteboard = get_pasteboard_driver()()
        with self.context():
            pasteboard.write('bar')

    def assert_expected_data(self, data, created=None, modified=None):
        now = datetime.datetime.today()
        if created is None:
            created = now
        if modified is None:
            modified = now

        self.assertEqual(1, len(data))
        data = data[0]
        self.assertEqual([u'foo'], data['names'])
        self.assertLess(1, (created - data['created']).total_seconds)
        self.assertEqual(1, len(data['vals']))
        date, val = data['vals'].items()[0]
        self.assertLess(1, (modified - date).total_seconds)
        self.assertEqual('bar', val)

    def test_default_dates(self):
        with backend('plaintext'), self.temporary_file('[]') as fp:
            args = ('-f', fp, 'new', '-n', 'foo', '-s', 'pasteboard')
            rv, stdout, stderr = safe(*args)
            with open(fp) as f:
                data = load_json(f)
        self.assertEqual(0, rv)
        self.assertEqual('', stdout)
        self.assertEqual('', stderr)
        self.assert_expected_data(data)

    def test_fully_specified(self):
        with backend('plaintext'), self.temporary_file('[]') as fp:
            rv, stdout, stderr = safe(
                '-f',
                fp,
                'new',
                '-c',
                '2014-01-01',
                '-m',
                '2014-01-02',
                '-n',
                'foo',
                '-s',
                'pasteboard',
            )
            with open(fp) as f:
                data = load_json(f)
        self.assertEqual(0, rv)
        self.assertEqual('', stdout)
        self.assertEqual('', stderr)
        self.assert_expected_data(
            data,
            datetime.datetime(2014, 1, 1),
            datetime.datetime(2014, 1, 2),
        )

    def test_import_failed(self):
        def read():
            raise ImportStrategyFailedError('foo')

        pasteboard = get_pasteboard_driver()
        with mock.patch.object(pasteboard, 'read', side_effect=read):
            args = ('-fx', 'new', '-n', 'foo', '-s', 'pasteboard')
            rv, stdout, stderr = safe(*args)
        self.assertEqual(42, rv)
        self.assertEqual('', stdout)
        self.assertEqual('error: foo\n', stderr)

    def test_prompt_for_name(self):
        answers = ['', 'foo']

        def raw_input_mock(_):
            return answers.pop(0)

        prompt_call = mock.call('Name for the new secret: ')
        name = '__builtin__.raw_input'
        with mock.patch(name, side_effect=raw_input_mock) as raw_input:
            with backend('plaintext'), self.temporary_file('[]') as fp:
                rv, stdout, stderr = safe('-f', fp, 'new', '-s', 'pasteboard')
                with open(fp) as f:
                    data = load_json(f)
        self.assertEqual(0, rv)
        self.assertEqual('', stdout)
        self.assertEqual('error: secret must have a name\n', stderr)
        self.assertEqual([prompt_call] * 2, raw_input.call_args_list)
        self.assert_expected_data(data)

    def test_unknown_dates(self):
        cases = ('-c', 'created', 40), ('-m', 'modified', 41)
        fmt = 'error: could not understand %s date (try YYYY-MM-DD)\n'
        for flag, name, expected_rv in cases:
            rv, stdout, stderr = safe('-fx', 'new', flag, 'abcdefg')
            self.assertEqual(expected_rv, rv)
            self.assertEqual('', stdout)
            self.assertEqual(fmt % name, stderr)
