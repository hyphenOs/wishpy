from setuptools import setup, find_packages

import wspy

setup(name='wspy',
        version='0.0.1',
        description='Python Bindings for Wireshark using CFFI',
        author='Abhijit Gadgil',
        author_email='gabhijit@iitbombay.org',
        license_files=['LICENSE', 'COPYING', 'COPYING-wireshark'],
        ext_modules=[wspy.wireshark.epan.epan.epan_ffi.distutils_extension()],
        packages=find_packages())

