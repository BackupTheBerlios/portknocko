#!/usr/bin/env python

import sys
from distutils.core import setup, Extension

# Assume inttypes.h exists and defines the uintXX_t types... FIXME
defines = [('HAVE_INTTYPES_H', 1)]
if sys.byteorder == 'big':
    defines.append(('WORDS_BIGENDIAN', None))

setup(name="shax-py", version = "0.92",
      url="http://www.saddi.com/software/",
      author="Allan Saddi",
      author_email="allan@saddi.com",
      description="Python modules for SHA256, SHA384, SHA512",
      license="BSD",
      long_description="""This is a collection of Python modules that implement
the NIST's draft SHA256, SHA384, and SHA512 standards.
The interface is the same as the sha module. SWIG
interface files (.i) are included but are not used due to
broken distutils support.""",
      py_modules=["sha256", "sha384", "sha512"],
      ext_modules=[Extension("sha256c", ["sha256c.c", "sha256.c"],
                             define_macros=defines),
                   Extension("sha384c", ["sha384c.c", "sha384.c"],
                             define_macros=defines),
                   Extension("sha512c", ["sha512c.c", "sha512.c"],
                             define_macros=defines)])
