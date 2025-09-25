# tests/test_sanity.py
import importlib


def test_import_package():
    assert importlib.import_module("docker_scanner")


def test_true():
    assert True
