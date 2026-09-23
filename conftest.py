"""Puts the repository root on sys.path so the tests can import lacre.

pytest prepends the directory of every conftest.py it loads; this file exists
for that side effect alone.
"""
