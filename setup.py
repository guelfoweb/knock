#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
	name="knockpy",
	version="5.4.0",
	description="Knock is a python tool designed to quickly enumerate subdomains on a target domain through dictionary attack.",
	url="https://github.com/guelfoweb/knock",
	author="Gianni 'guelfoweb' Amato",
	license="GPL-3.0",
	packages=["knockpy"],
	package_data={
		"knockpy": [
			"wordlist.txt",
			"config.json",
			], 
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
