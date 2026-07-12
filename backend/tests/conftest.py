"""
Pytest configuration and fixtures
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture
def app():
    """Create and configure a test app instance.

    The app import happens lazily so test files that don't touch the Flask
    app (e.g. the frontend DOM contract tests) can run without the backend
    dependencies installed.
    """
    from app import create_app
    from app.config import TestingConfig

    app = create_app(TestingConfig)
    app.config['TESTING'] = True
    yield app


@pytest.fixture
def client(app):
    """Create a test client for the app"""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create a test CLI runner"""
    return app.test_cli_runner()

