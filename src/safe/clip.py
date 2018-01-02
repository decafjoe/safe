# -*- coding: utf-8 -*-
"""
Clipboard drivers.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import os
import subprocess

from clik.compat import iteritems
from clik.util import AttributeDict

from safe.util import get_executable, Subprocess, temporary_directory


class ClipboardError(Exception):
    """Raised for errors occurring in this module."""


def sorted_by_precedence(values):
    """
    Return ``values`` sorted ascending by their ``precedence`` property.

    :param values: Sequence of values to sort (each value must have a
                   ``precedence`` property)
    :return: Sorted list of values
    :rtype: :class:`list`
    """
    return sorted(values, key=lambda value: -value.precedence)


class Registry(AttributeDict):
    """Registry for clipboard drivers."""

    def register(self, cls):
        """
        Register a clipboard driver.

        :param safe.clip.Driver cls: Driver class
        :raises: :exc:`ClipboardError` if driver with class' ``name`` has
                 already been registered
        :return: Class that was passed in
        """
        if cls.name in self:
            fmt = 'Clipboard driver "%s" already registered'
            raise ClipboardError(fmt % cls.name)
        self[cls.name] = cls
        return cls

    @property
    def supported(self):
        """
        List of supported drivers, sorted by precedence.

        :type: :class:`list` of :class:`safe.clip.Driver` classes
        """
        drivers = [cls for cls in self.values() if cls.supported]
        return sorted_by_precedence(drivers)

    @property
    def preferred(self):
        """
        Preferred clipboard driver for the system.

        :type: :class:`safe.clip.Driver`
        """
        return sorted_by_precedence(self.supported)[0]

    def configure_parser(self, parser):
        """
        Configure argument parser with clipboard arguments.

        The arguments allow the end user to select how clipboard operations
        are done.

        If there are multiple supported drivers, the ``--driver`` argument
        is added to allow the user to select the driver to use. If there is
        only one driver, the ``--driver`` argument is omitted and only the
        driver-specific arguments are configured.

        :param argparse.ArgumentParser parser: Parser to configure
        :raises: :exc:`ClipboardError` if there are no supported clipboards
        """
        if not self:
            raise ClipboardError('no supported clipboards')

        choices = sorted([cls.name for cls in self.supported])
        if len(choices) > 1:
            choices_str = ', '.join(choices)
            parser.add_argument(
                '-d',
                '--driver',
                choices=choices,
                default=self.preferred.name,
                help='clipboard driver to use (choices: %s) (default: '
                     '%%(default)s)' % choices_str,
            )

        for cls in self.supported:
            cls.configure_parser(parser)

    def driver_for_args(self, args):
        """
        Return clipboard driver for given arguments.

        :param argparse.Namespace args: Arguments supplied by end user
        :return: Clipboard driver configured per arguments
        :rtype: :class:`safe.clip.Driver`
        """
        if len(self.supported) > 1:
            cls = self[args.driver]
        else:
            cls = self.supported[0]
        params = {}
        for name, kwargs in iteritems(cls.parameters):
            args_name = '%s_%s' % (cls.name, name)
            value = getattr(args, args_name, None)
            if value is not None:
                params[name] = value
        return cls(**params)


#: Global registry for clipboard drivers.
#:
#: :type: :class:`Registry`
clipboard_drivers = Registry()


def run(command, stdin=None):
    """
    Run a command, send it ``stdin``, return exit code, stdout, and stderr.

    :param command: String or sequence of strings representing the command
    :param stdin: Optional value to send to stdin
    :type stdin: :class:`str` or ``None``
    :return: 3-tuple ``(returncode, stdout, stderr)``
    """
    with temporary_directory() as tmp:
        stdout_path = os.path.join(tmp, 'stdout')
        stderr_path = os.path.join(tmp, 'stderr')
        with open(stdout_path, 'w') as stdout_f, \
             open(stderr_path, 'w') as stderr_f:  # noqa: E127
            process = Subprocess(
                command,
                stdin=subprocess.PIPE,
                stdout=stdout_f,
                stderr=stderr_f,
            )
            process.communicate(stdin)
        with open(stdout_path) as f:
            stdout = f.read()
        with open(stderr_path) as f:
            stderr = f.read()
        return process.returncode, stdout, stderr


class Driver(object):
    """Driver base class."""

    #: Human-friendly name of the driver.
    #:
    #: :type: :class:`str`
    name = None

    #: Precedence of the driver. This is used to figure out the default
    #: driver if multiple drivers are supported on a system. The
    #: driver with the highest precedence is considered the preferred
    #: driver.
    #:
    #: :type: :class:`int`
    precedence = 0

    #: Parameters for the driver. This is used to expose configuration
    #: options to end users as well as define defaults.
    #:
    #: The parameters dict maps ``name -> dict()``, where the dict is
    #: the configuration for the parameter. Configs can have
    #: ``description`` and ``default`` keys, which set the help
    #: message and default value, respectively.
    #:
    #: When the driver is instantiated, the parameters are available
    #: in ``self.param``.
    #:
    #: See :class:`Pasteboard` or :class:`Xclip` for examples.
    #:
    #: :type: :class:`dict`
    parameters = None

    #: Indicates whether driver is supported.
    #:
    #: :type: :class:`bool`
    supported = False

    #: (instance) Parameter values for this instance of the driver.
    #: Params are composed of the default values, overridden by anything
    #: passed into the constructor.
    #:
    #: :type: :class:`clik.AttributeDict`
    param = None

    @classmethod
    def configure_parser(cls, parser):
        """
        Configure parameter arguments on ``parser``.

        :param argparse.ArgumentParser parser: Parser to configure
        """
        for name, kwargs in iteritems(cls.parameters):
            kwargs.setdefault('metavar', name.upper())
            name = name.replace('_', '-')
            parser.add_argument('--%s-%s' % (cls.name, name), **kwargs)

    def __init__(self, **kwargs):
        """
        Instantiate the driver.

        :param kwargs: Parameters (overrides defaults set in
                       :attr:`parameters`)
        """
        self.param = AttributeDict()
        if self.parameters:
            defaults = {}
            for name, param_kwargs in iteritems(self.parameters):
                if 'default' in param_kwargs:
                    defaults[name] = param_kwargs['default']
            self.param.update(defaults)
        self.param.update(kwargs)

    def get(self):
        """
        Stub method for getting data from the clipboard.

        :raises: :exc:`NotImplementedError`
        """
        raise NotImplementedError

    def put(self, value):
        """
        Stub method for putting data on the clipboard.

        :param str value: Value to put on the clipboard
        :raises: :exc:`NotImplementedError`
        """
        raise NotImplementedError


class Pasteboard(Driver):
    """Clipboard driver using pbcopy and pbpaste, found on macOS systems."""

    #: Absolute path to the ``pbcopy`` executable, or ``None`` if not
    #: found on the system.
    #:
    #: :type: :class:`str` or ``None``
    pbcopy = get_executable('pbcopy')

    #: Absolute path to the ``pbpaste`` executable, or ``None`` if not
    #: found on the system.
    #:
    #: :type: :class:`str` or ``None``
    pbpaste = get_executable('pbpaste')

    #: This driver is supported if pbcopy and pbpaste are present.
    supported = pbcopy is not None and pbpaste is not None

    name = 'pb'
    precedence = 1000
    parameters = dict(
        board=dict(
            default='general',
            help='clipboard to use (default: %(default)s)',
        ),
    )

    def get(self):
        """Return data on the pasteboard."""
        rc, stdout, stderr = run((self.pbpaste, '-pboard', self.param.board))
        if rc:
            fmt = '%s failed with stderr: %s'
            raise ClipboardError(fmt % (self.pbpaste, stderr))
        return stdout

    def put(self, value):
        """
        Put data on the pasteboard.

        :param str value: Value to put on the pasteboard
        """
        command = (self.pbcopy, '-pboard', self.param.board)
        rc, _, stderr = run(command, stdin=value)
        if rc:
            fmt = '%s failed with stderr: %s'
            raise ClipboardError(fmt % (self.pbcopy, stderr))


class Xclip(Driver):
    """Clipboard driver using xclip from the X Window System."""

    #: Absolute path to the ``xclip`` executable, or ``None`` if not
    #: found on the system.
    #:
    #: :type: :class:`str` or ``None``
    xclip = get_executable('xclip')

    #: This driver is supported if the xclip executable is present.
    supported = xclip is not None

    name = 'xclip'
    parameters = dict(
        selection=dict(
            default='clipboard',
            help='X selection to use (default: %(default)s)',
        ),
    )

    def get(self):
        """Return data on the clipboard."""
        command = (self.xclip, '-out', '-selection', self.param.selection)
        rc, stdout, stderr = run(command)
        if rc:
            fmt = '%s failed with stderr: %s'
            raise ClipboardError(fmt % (self.xclip, stderr))
        return stdout

    def put(self, value):
        """
        Put data on the clipboard.

        :param str value: Value to put on the clipboard
        """
        command = (self.xclip, '-in', '-selection', self.param.selection)
        rc, _, stderr = run(command, stdin=value)
        if rc:
            fmt = '%s failed with stderr: %s'
            raise ClipboardError(fmt % (self.xclip, stderr))


clipboard_drivers.register(Pasteboard)
clipboard_drivers.register(Xclip)
