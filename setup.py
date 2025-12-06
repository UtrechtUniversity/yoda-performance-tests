from setuptools import setup

setup(
    name='yoda_performance_tests',
    version='0.3',
    py_modules=['main'],
    install_requires=[
        'python-irodsclient==3.1.1',
        'urllib3==2.6.0',
        'requests==2.32.4',
        'webdavclient3',
        'matplotlib==3.10.3',
    ],
    entry_points={
        'console_scripts': [
            'yoda_performance_tests=main:main',
        ],
    },
    description='Performance testing for Yoda.',
    url='https://github.com/UtrechtUniversity/yoda-performance-tests',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    ],
    python_requires='>=3.6',
)
