# Copyright (c) 2008 Infrae. All rights reserved.
# See also LICENSE.txt
# $Id$

from setuptools import setup, find_packages, Extension
import os

version = '1.0dev'

tests_require = [
    'Products.Silva [test]',
    ]

setup(name='silva.pas.kerberos5',
      version=version,
      description="Kerberos 5 authentication for PAS in Silva CMS",
      long_description=open("README.txt").read() + "\n" +
                       open(os.path.join("docs", "HISTORY.txt")).read(),
      classifiers=[
        "Framework :: Zope2",
        "Programming Language :: C",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: BSD License",
        ],
      keywords='kerberos5 pas silva',
      author='Sylvain Viollon',
      author_email='info@infrae.com',
      url='https://github.com/silvacms/silva.pas.kerberos5',
      license='BSD',
      package_dir={'': 'src'},
      packages=find_packages('src'),
      namespace_packages=['silva', 'silva.pas'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
        "setuptools",
        "zope.interface",
        "Products.PluggableAuthService",
        ],
      tests_require = tests_require,
      extras_require = {'test': tests_require},
      ext_modules = [Extension('silva.pas.kerberos5._kerberos5',
                               sources = ['src/silva/pas/kerberos5/_kerberos5.c'],
                               libraries = ['com_err', 'k5crypto', 'krb5'])
                     ],
      )
