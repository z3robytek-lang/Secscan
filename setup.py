from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="secscan",
    version="0.1.0",
    author="z3robytek-lang",
    description="Security Configuration Validator - Validate configurations against security best practices",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/z3robytek-lang/secscan",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0",
        "pyyaml>=6.0",
        "jinja2>=3.0",
        "colorama>=0.4",
        "tabulate>=0.9",
    ],
    entry_points={
        "console_scripts": [
            "secscan=secscan.cli:main",
        ],
    },
)
