import os
import pytest
import logging
from six import StringIO


@pytest.fixture
def fixture_dir():
    return os.path.abspath(
           os.path.join(
             os.path.dirname(__file__), 'fixture'))


mock_connection_params = {
    "org_id": "N/A",
    "auth": "N/A",
    "user_management_endpoint": 'https://test/',
    "logger": None,
    "retry_max_attempts": 3,
    "retry_first_delay": 1,
    "retry_random_delay": 2,
}


class MockResponse:
    def __init__(self, status=200, body=None, headers=None, text=None):
        self.status_code = status
        self.body = body if body is not None else {}
        self.headers = headers if headers else {}
        self.text = text if text else ""

    def json(self):
        return self.body


# py.test doesn't divert string logging, so use it
@pytest.fixture
def log_stream():
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger('test_logger')
    logger.setLevel(logging.WARNING)
    logger.addHandler(handler)
    yield stream, logger
    handler.close()
