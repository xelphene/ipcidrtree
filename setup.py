#!/usr/bin/env python

from distutils.core import setup
import sys

if sys.argv[1]=='sdist':
  sys.path = ['.'] + sys.path
  import iptree.__init__
  version = iptree.__init__.__version__
else:
  version = '0.0.0'

setup(name='iptree',
      version=version,
      description='Class for representing IPv4 addresses and netmasks, particularly in tree structures organized by CIDR hierarchy',
      author='Steve Benson',
      author_email='steve@rhythm.cx',
      license='New-style BSD',
      url='http://www.rhythm.cx/~steve/devel/iptree',
      packages=['iptree/']
     )
