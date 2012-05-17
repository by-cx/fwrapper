import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "fwrapper",
    version = "0.1",
    author = "Adam Strauch",
    author_email = "cx@initd.cz",
    description = ("Wrapper tool for iptables"),
    license = "BSD",
    keywords = "iptables,ip6tables,firewall",
    url = "https://github.com/creckx/uWSGI-Manager",
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    long_description="Make iptables rules more easier to maintain.",#read('README'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: BSD License",
    ],
    install_requires=[
        #"termcolor",
        ],
    entry_points="""
    [console_scripts]
    fwrapper = fwrapper.fwrapper:main
    """
)