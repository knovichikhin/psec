from setuptools import setup, find_packages
from psec import __version__

classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: Implementation :: CPython",
    "Programming Language :: Python :: Implementation :: PyPy",
    "Topic :: Security :: Cryptography",
    "Topic :: Software Development :: Libraries :: Python Modules",
]

if __name__ == "__main__":

    with open("README.rst", "r", encoding="utf-8") as f:
        readme = f.read()

    setup(
        name="psec",
        version=__version__,
        author="Konstantin Novichikhin",
        author_email="konstantin.novichikhin@gmail.com",
        description="A Python package for cryptography in payment systems",
        long_description=readme,
        long_description_content_type="text/x-rst",
        license="MIT",
        url="https://github.com/knovichikhin/psec",
        packages=find_packages(exclude=["tests"]),
        package_data={"psec": ["py.typed"]},
        zip_safe=False,
        install_requires=[
            "cryptography >= 1.0",
        ],
        classifiers=classifiers,
        python_requires=">=3.6",
        keywords="payment security cvv cvd cvc mac iso9797 tdes aes tr31",
    )
