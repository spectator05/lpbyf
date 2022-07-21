from setuptools import setup, find_packages

setup(
    name="lpbyf",
    version="0.2.0",
    description="Label pcaps by flow",
    license="MIT",
    author="Woohyuk Jang",
    author_email="spectat@kookmin.ac.kr",
    package_dir={"": "src"},
    url="https://github.com/spectator05/lpbyf",
    keywords="pcacp",
    install_requires=[
        "scapy",
    ],
)
