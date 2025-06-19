# setup.py

from setuptools import setup, find_packages

setup(
    name="Nectar2P",
    version="1.1.0",
    description="A secure P2P file transfer library with optional encryption and NAT traversal support",
    author="Glimor",
    author_email="glimor@proton.me",
    url="https://github.com/Glimor/Nectar2P", 
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "setuptools",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries",
        "Topic :: Communications :: File Sharing",
        "Natural Language :: English",
    ],
    python_requires='>=3.6',
    keywords="p2p file transfer, secure file sharing, end-to-end encryption, NAT traversal, AES encryption, cryptography, hole punching, firewall traversal, cross-platform",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
)
