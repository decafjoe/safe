from setuptools import setup


project = 'safe'
version = '0.2'
requires = (
    'clik==0.4-alpha.2',
    'pexpect==3.3',
    'pynacl==0.2.3',
)


setup(
    author='Joe Strickler',
    author_email='joe@decafjoe.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    description='Command-line program for storing sensitive data.',
    entry_points={
        'console_scripts': [
            '%(project)s = %(project)s:main' % {'project': project},
        ],
    },
    install_requires=requires,
    license='BSD',
    long_description=open('README.rst').read(),
    name=project,
    package_dir={'': 'src'},
    py_modules=[project],
    test_suite='test',
    url='https://bitbucket.org/decafjoe/%s' % project,
    version=version,
    zip_safe=False,
)
