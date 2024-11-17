from setuptools import setup
import os

wordlist = 'wordlist' + os.sep + 'wordlist.txt'

setup(
    name='knock-subdomains',
    version='7.0.2',
    description='Knockpy Subdomains Scan',
    url='https://github.com/guelfoweb/knock',
    author='Gianni Amato',
    author_email='guelfoweb@gmail.com',
    license='GPL-3.0',
    packages=['knock'],
    package_data={"knock": [wordlist, 'report'],},
    include_package_data=True,
    install_requires=[
        'requests>=2.31.0', 
        'dnspython>=2.4.2', 
        'pyOpenSSL>=23.3.0', 
        'beautifulsoup4>=4.12.3', 
        'tqdm>=4.66.2'],
    entry_points={
        'console_scripts': [
            'knockpy=knock.knockpy:main',
        ],
    }
)
