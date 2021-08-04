#!/usr/bin/python3
from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

with open('LICENSE.md') as f:
    lic = f.read()

setup(name='spysecli',
      version='0.0.1',
      description='CLI for spyse.com',
      long_description=readme,
      long_description_content_type='text/markdown',
      license=lic,
      author='Roman Romanov',
      author_email='roman.romanov@spyse.com',
      url='https://github.com/spyse-com/spyse-cli',
      packages=find_packages(exclude=('tests', 'examples')),
      entry_points={
          'console_scripts': ['spysecli=bin.main:main'],
      },
      install_requires=['spyse-python~=2.0.1', 'loguru~=0.5.3', 'validators~=0.18.2', 'click~=8.0.1']
      )
