import os
import re
from io import open

from setuptools import find_packages, setup


def read(f):
    return open(f, "r", encoding="utf-8").read()


def get_version(package):
    """
    Return package version as listed in `__version__` in `init.py`.
    """
    init_py = open(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            os.path.join(package, "__init__.py"),
        )
    ).read()
    return re.search("__version__ = ['\"]([^'\"]+)['\"]", init_py).group(1)


version = get_version("dbmi_client")

setup(
    name="django-dbmi-client",
    version=version,
    url="https://github.com/hms-dbmi/django-dbmi-client",
    author="HMS DBMI Tech-core",
    author_email="dbmi-tech-core@hms.harvard.edu",
    packages=find_packages(exclude=["tests*"]),
    license="Creative Commons Attribution-Noncommercial-Share Alike license",
    install_requires=read("requirements.txt").splitlines(),
    tests_require=read("requirements-test.txt").splitlines(),
    extras_require={
        "test": read("requirements-test.txt").splitlines(),
        "dev": read("requirements-dev.txt").splitlines(),
    },
    test_suite="dbmi_client.tests.runtests.main",
    include_package_data=True,
    classifiers=[
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 2.2",
        "Framework :: Django :: 3",
        "Framework :: Django :: 4",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",  # example license
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
)
