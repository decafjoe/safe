# -*- coding: utf-8 -*-
"""
Package configuration for decafjoe-safe.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import os

from setuptools import find_packages, setup


name = 'decafjoe-safe'
version = '0.6.2'
requires = (
    'clik==0.92.2',
    'clik-shell==0.90.0',
    'clik-wtforms==0.90.1',
    'sqlalchemy==1.2.1',
    'wtforms==2.1',
)

url = 'https://%s.readthedocs.io' % name
description = 'Password manager for people who like GPG and the command line.'
long_description = 'Please see the official project page at %s' % url

root_dir = os.path.abspath(os.path.dirname(__file__))
src_dir = os.path.join(root_dir, 'src')
packages = find_packages(src_dir)

package_name = 'safe'
entry_point = '%(name)s = %(name)s:main' % dict(name=package_name)

setup(
    author='Joe Joyce',
    author_email='joe@decafjoe.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: PyPy',
    ],
    description=description,
    entry_points=dict(console_scripts=[entry_point]),
    install_requires=requires,
    license='BSD',
    long_description=long_description,
    name=name,
    package_dir={'': 'src'},
    packages=packages,
    url=url,
    version=version,
    zip_safe=False,
)
