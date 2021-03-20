#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
	name="knockpy",
	version="5.0.0",
	description="Knock is a python tool designed to enumerate subdomains on a target domain through dictionary attack.",
	url="https://github.com/guelfoweb/knock",
	author="Gianni 'guelfoweb' Amato",
	license="MIT",
	packages=["knockpy"],
	package_data={
		"knockpy": [
			"wordlist.txt",
			"config.json",
			], 
	},
	install_requires = [
			"requests",
			"bs4",
			"colorama"
			],
	python_requires=">=3.6",
	entry_points={
		'console_scripts': [
			'knockpy=knockpy.knockpy:main',
		],
	}
)
