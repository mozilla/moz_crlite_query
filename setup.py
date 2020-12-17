from setuptools import setup


setup(
    name="moz_crlite_query",
    version="0.4.2",
    description="Query CRLite for a certificate, or certificate information",
    long_description="Use this tool to download and maintain CRLite information from "
    + "Mozilla's Remote Settings infrastructure, and query it.",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Programming Language :: Python :: 3",
    ],
    keywords="bloom filter cascade multi level mlbf crlite",
    url="http://github.com/mozilla/moz_crlite_query",
    author="J.C. Jones",
    author_email="jc@mozilla.com",
    license="Mozilla Public License 2.0 (MPL 2.0)",
    zip_safe=False,
    include_package_data=True,
    python_requires=">=3.7",
    install_requires=[
        "deprecated",
        "filtercascade",
        "glog",
        "moz-crlite-lib",
        "progressbar2",
        "pyasn1-modules",
        "requests",
    ],
    packages=["crlite_query"],
    entry_points={
        "console_scripts": ["moz_crlite_query=crlite_query.query_cli:main"],
    },
)
