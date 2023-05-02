#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='enoceanjob',
    version='0.60.11',
    description='EnOcean serial protocol implementation',
    author='Kimmo Huoman',
    author_email='jo.binon@gmail.com',
    url='https://github.com/Darki03/enocean_job',
    packages=[
        'enoceanjob',
        'enoceanjob.protocol',
        'enoceanjob.communicators',
    ],
    scripts=[
        'examples/enocean_example.py',
    ],
    package_data={
        '': ['EEP.xml'],
        '': ['eep268.xml']
    },
    install_requires=[
        'enum-compat>=0.0.2',
        'pyserial>=3.0',
        'beautifulsoup4>=4.3.2',
    ])
