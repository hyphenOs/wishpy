from setuptools import setup, find_packages

setup(name='wspy',
        version='0.0.1',
        description='Python Bindings for Wireshark using CFFI',
        author='Abhijit Gadgil',
        author_email='gabhijit@iitbombay.org',
        license_files=['LICENSE', 'COPYING', 'COPYING-wireshark'],
        setup_requires=['cffi>=1.14.0'],
        install_requires=['cffi>=1.14.0'],
        cffi_modules=[
            'wspy/wireshark/src/epan/epan_builder.py:epan_ffi',
            'wspy/wireshark/src/wtap/wtap_builder.py:wtap_ffi',
            ],
        packages=find_packages(exclude=('wspy.wireshark.lib',)),
        scripts=['examples/tshark.py'],
        zip_safe=False)

