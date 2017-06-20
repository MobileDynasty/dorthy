import os

from distutils.core import setup
from setuptools import find_packages

version = "0.7.7"


def strip_comments(l):
    return l.split('#', 1)[0].strip()


def reqs(f):
    return list(filter(None, [strip_comments(l) for l in open(
        os.path.join(os.getcwd(), f)).readlines()]))

install_requires = reqs("requirements.txt")

setup(
    name='dorthy',
    version=version,
    packages=find_packages(exclude=['ez_setup', 'tests', 'tests.*']),
    url='https://github.com/MobileDynasty/dorthy',
    author='dev@mobile-dynasty.com',
    author_email='dev@mobile-dynasty.com',
    license='MIT',
    description="a micro web framework for Tornado",
    long_description='a micro web framework for Tornado',
    keywords='web framework development',
    install_requires=install_requires,
    zip_safe=False,
    classifiers=[
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Topic :: Internet :: WWW/HTTP',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4'
    ]
)
