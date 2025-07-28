from setuptools import setup, find_packages

setup(
    name="fernet256",
    version="3.0.0",
    author="xRangeroQ",
    description="Simplified AES-256 encryption tool inspired by Fernet",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/xRangeroQ/fernet256",
    packages=find_packages(),
    install_requires=[
        "pycryptodome>=3.23.0"
    ],
    python_requires=">=3.9",
)
