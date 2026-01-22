#!/usr/bin/env python3
"""
Bounty Buddy - Bug Bounty Security Testing Toolkit
Setup configuration for package installation

SPDX-License-Identifier: MIT
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = []
with open('requirements.txt') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="bounty-buddy",
    version="2.0.0",
    author="Bounty Buddy Contributors",
    description="Comprehensive bug bounty security testing toolkit with IoT capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bounty-buddy/bounty-buddy",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "bountybuddy=bountybuddy.cli:app",
            "wsdiscovery=tools.iothackbot.wsdiscovery:wsdiscovery",
            "onvifscan=tools.iothackbot.onvifscan:onvifscan",
        ],
    },
)
