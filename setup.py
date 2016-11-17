# -*- coding: utf-8 -*-
"""
Package configuration for safe.

:author: Joe Strickler <joe@decafjoe.com>
:copyright: Joe Strickler, 2016. All rights reserved.
:license: Proprietary
"""
from setuptools import setup


name = 'safe'
version = '0.2.0'
requires = (
    'arrow==0.8.0',
    'clik==0.5-alpha.2',
    'pexpect==4.2.1',
    'python-dateutil==2.6.0',
    'sqlalchemy==1.1.4',
    'sqlalchemy-utils==0.32.9',
)


setup(
    author='Joe Strickler',
    author_email='joe@decafjoe.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: Other/Proprietary License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    description='Command-line program for storing sensitive data.',
    entry_points={
        'console_scripts': [
            '%(name)s = %(name)s:%(name)s.main' % {'name': name},
        ],
    },
    install_requires=requires,
    license='Proprietary',
    long_description=open('README.rst').read(),
    name=name,
    package_dir={'': 'src'},
    py_modules=[name],
    test_suite='test',
    url='https://bitbucket.org/decafjoe/%s' % name,
    version=version,
    zip_safe=False,
)
