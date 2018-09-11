from distutils.core import setup
from setuptools import find_packages

setup(
    name='django-dbmi-client',
    version='0.1.0',
    url='https://github.com/hms-dbmi/django-dbmi-client',
    author='HMS DBMI Tech-core',
    author_email='dbmi-tech-core@hms.harvard.edu',
    packages=[
        'dbmi_client',
    ],
    license='Creative Commons Attribution-Noncommercial-Share Alike license',
    install_requires=[
        'django>=1.10.0',
        'djangorestframework>=1.9.0',
        'cryptography',
        'requests',
        "jwcrypto",
        "furl",
        "pyjwt",
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: X.Y',  # replace "X.Y" as appropriate
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',  # example license
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
