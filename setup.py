#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup
import os

# local wordlist
local = "local{sep}*.txt".format(sep=os.sep)
# remote wordlist
remote = "remote{sep}*.py".format(sep=os.sep)
# lib
lib = "lib{sep}*.py".format(sep=os.sep)

setup(
	name="knockpy",
	version="6.1.0",
	description="Knock is a Knockpy is a portable and modular python3 tool designed to quickly enumerate subdomains on a target domain through passive reconnaissance and dictionary attack.",
	url="https://github.com/guelfoweb/knock",
	author="Gianni 'guelfoweb' Amato",
	license="GPL-3.0",
	packages=["knockpy"],
	package_data={
		"knockpy": [lib, local, remote],
	},
	include_package_data=True,
	install_requires = [
			"requests",
			"beautifulsoup4",
			"colorama",
			],
	python_requires=">=3.6",
	entry_points={
		'console_scripts': [
			'knockpy=knockpy.knockpy:main',
		],
	}
)
