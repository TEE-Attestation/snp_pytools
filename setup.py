from setuptools import find_packages, setup

setup(
    name="snp_pytools",
    version="0.4.1",
    packages=find_packages(),
    install_requires=[
        "requests",
        "cryptography>=39.0.0",
    ],
    entry_points={
        "console_scripts": [
            "snp-fetch=snp_pytools.fetch:main",
            "snp-print=snp_pytools.print_report:main",
            "snp-verify=snp_pytools.verify:main",
        ],
    },
    description="Python tools for AMD SEV-SNP attestation",
    url="https://github.com/Isaac-Matthews/snp_pytools",
    author="Isaac Matthews",
    author_email="isaac@hpe.com",
    license="Apache-2.0",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
    ],
)
