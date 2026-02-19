from setuptools import setup, find_packages

setup(
    name="lightscan",
    version="2.0.0",
    description="Autonomous red-team reconnaissance and attack framework",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Light",
    author_email="ne0k1r4@proton.me",
    url="https://github.com/ne0k1r4/LightScan",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.10",
    entry_points={"console_scripts": ["lightscan=lightscan.cli:main"]},
    install_requires=[],  # zero hard deps — stdlib only
    extras_require={
        "full": [
            "paramiko==3.4.0",
            "pymysql==1.1.1",
            "psycopg2-binary==2.9.9",
            "impacket==0.12.0",
            "ldap3==2.9.1",
            "pycryptodome==3.20.0",
            "pymssql==2.3.0",
            "scapy==2.5.0",
            "aiohttp==3.9.5",
            "PyYAML==6.0.1",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
# python pin
