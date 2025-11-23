#!/usr/bin/env python3
"""
IoTHackBot - IoT Security Testing Toolkit
Setup configuration for package installation
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
    name="iothackbot",
    version="1.0.0",
    author="BrownFine Security",
    description="Open-source IoT security testing toolkit with integrated Claude Code skills",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/BrownFineSecurity/iothackbot",
    packages=find_packages(where="tools"),
    package_dir={"": "tools"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.1.0",
            "mypy>=1.5.0",
            "isort>=5.12.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "wsdiscovery=iothackbot.wsdiscovery:wsdiscovery",
            "onvifscan=iothackbot.onvifscan:onvifscan",
            "iotnet=iothackbot.iotnet:iotnet",
            "ffind=iothackbot.ffind:ffind",
        ],
    },
    include_package_data=True,
    package_data={
        "iothackbot": [
            "config/iot/*.json",
            "wordlists/*.txt",
        ],
    },
    keywords="iot security penetration-testing onvif network-scanning vulnerability-assessment",
    project_urls={
        "Bug Reports": "https://github.com/BrownFineSecurity/iothackbot/issues",
        "Source": "https://github.com/BrownFineSecurity/iothackbot",
    },
)
