"""Compatibility shim for legacy toolchains.

Metadata lives in pyproject.toml (PEP 621) and setup.cfg. This file exists so
`setup.py`-based build paths still resolve correctly — notably `setup.py
develop`, which pip < 21.3 uses for `pip install -e` because it predates
PEP 660 editable installs.
"""
from setuptools import setup

setup()
