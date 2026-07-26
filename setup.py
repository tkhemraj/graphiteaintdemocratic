from setuptools import setup, find_packages

setup(
    name="graphiteaintdemocratic",
    version="0.1.0",
    packages=find_packages(),
    package_data={
        "graphiteaintdemocratic": ["iocs/*.txt"],
    },
    entry_points={
        "console_scripts": [
            "gaid=graphiteaintdemocratic.cli:main",
        ],
    },
    install_requires=[
        "dpkt>=1.9.8",
    ],
    extras_require={
        "dev": ["pytest", "pytest-cov"],
    },
    python_requires=">=3.11",
)
