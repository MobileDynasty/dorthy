from distutils.core import setup
from setuptools import find_packages

version = "0.6.3"

install_requires = [
    "PyYAML",
    "tornado",
    "redis",
    "raven",
    "pycrypto",
    "SQLAlchemy",
    "jinja2",
    "py3k-bcrypt",
    "pytz"
]

setup(
    name='dorthy',
    version=version,
    packages=find_packages(),
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
