from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="zepy-security",
    version="1.0.0",
    author="4mm47",
    description="Advanced AI & LLM Static Application Security Testing (SAST) & Prompt Vulnerability Detection Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/4mm47/zepy",
    project_urls={
        "Bug Tracker": "https://github.com/4mm47/zepy/issues",
        "Documentation": "https://github.com/4mm47/zepy#readme",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        "rich>=13.0.0",
        "PyQt5>=5.15.0",
        "safetensors>=0.4.0",
        "pydantic>=2.0.0",
        "PyYAML>=6.0.0",
    ],
    entry_points={
        "console_scripts": [
            "zepy-scan=zepy.cli:main",
            "zepy-gui=zepy.gui.app:run_gui",
            "zepy-shield=zepy.cli:main",
        ],
    },
    include_package_data=True,
)
