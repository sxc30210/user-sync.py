import os
import six
import pytest


@pytest.fixture
def fixture_dir():
    return os.path.abspath(
           os.path.join(
             os.path.dirname(__file__), 'fixture'))


def compare_dictionary(actual, expected):
    if len(actual) != len(expected):
        return False
    for key in actual:
        if key not in expected:
            return False
        elif isinstance(actual[key], dict):
            if not compare_dictionary(actual[key], expected[key]):
                return False
        elif isinstance(actual[key], list):
            if not compare_list(actual[key], expected[key]):
                return False
        else:
            if not actual[key]: actual[key] = None
            if not expected[key]: expected[key] = None
            if six.text_type(actual[key]) != six.text_type(expected[key]):
                return False
    return True

def compare_list(actual, expected):
    if len(actual) != len(expected):
        return False
    for act in actual:
        matched = False
        for exp in expected:
            if type(act) == type(exp):
                if isinstance(act, dict):
                    check = compare_dictionary(act, exp)
                elif isinstance(act, list):
                    check = compare_list(act, exp)
                else:
                    check = six.text_type(act) == six.text_type(exp)
                matched = True if check else matched
        if matched == False:
            return False

    return True