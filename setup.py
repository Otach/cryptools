#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from cryptools import __author__, __version__, __license__, __maintainer__, __maintainer_email__

setup(
    name='cryptools',
    version=__version__,
    description='Useful crypto tools for CTF crypto attacks',
    license=__license__,
    author=__author__,
    packages=find_packages(),
    install_requires=['pycryptodome', 'gmpy'],
    maintainer=__maintainer__,
    maintainer_email=__maintainer_email__
)
