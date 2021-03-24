#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ----------------------------------------------------------------------
# This file is part of Knock subdomain scan (aka knockpy)
#
# Knock is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Knock is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Knock. If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------

from setuptools import setup
from codecs import open  # To use a consistent encoding
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'CHANGELOG.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='knockpy',
    version='4.1.1',

    description='Knock is a python tool designed to enumerate subdomains on a target domain through a wordlist.',
    long_description=long_description,
    url='https://github.com/guelfoweb/knock',

    author='Gianni \'guelfoweb\' Amato',
    author_email='guelfoweb@gmail.com',

    license='GNU',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Production/Stable',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: GNU General Public License (GPL)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],

    keywords='knock sudbomain scan',

    packages=["knockpy", "knockpy.modules"],
    package_data={
		'knockpy': ['wordlist/*.txt', '*.json'], 
	},
    
	install_requires = ['dnspython>=1.3.5'],

    entry_points={
        'console_scripts': [
            'knockpy=knockpy.knockpy:main',
        ],
    },

)
