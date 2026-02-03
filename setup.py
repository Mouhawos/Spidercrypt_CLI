from setuptools import setup, find_packages

setup(
    name="spidercrypt-cli",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click"
    ],
    entry_points={
        "console_scripts": [
            "spidercrypt=spidercrypt_cli.cli:cli"
        ]
    },
    author="Spidercrypt",
    description="CLI de chiffrement Spidercrypt",
)
