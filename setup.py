from setuptools import setup

from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='setrace',
    version='0.0.1',
    description='A program to generate selinux policies for auditing all access vectors.',
    long_description=long_description,
    url='https://github.com/garyttierney/setrace-py',
    author='Gary Tierney',
    author_email='gary.tierney@gmx.com',

    # https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Operating System :: POSIX :: Linux',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],

    packages=["setrace"],
    entry_points={
        'console_scripts': [
            'setrace=setrace:main',
        ],
    },
)
