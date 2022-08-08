#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='sbom_tracer',
    version='1.0.0',
    author='sbom',
    packages=find_packages(),
    package_data={'': ['conf/default_command_config.yml']},
    install_requires=['click', 'PyYAML', 'six', 'hyperframe', 'hpack'],
    entry_points={
        'console_scripts': [
            'sbom_tracer = sbom_tracer.main:main',
        ]}
)
