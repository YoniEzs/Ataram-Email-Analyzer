"""
Test cases for the Flask application
"""
import pytest
from app import create_app
from app.config import TestingConfig


def test_app_creation():
    """Test that the app can be created"""
    app = create_app(TestingConfig)
    assert app is not None
    assert app.config['TESTING'] is True


def test_health_endpoint(client):
    """Test the /health endpoint"""
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'
    assert 'service' in data


def test_cors_headers(client):
    """Test that CORS headers are set correctly"""
    response = client.options('/api/analyze')
    assert response.status_code == 200


def test_404_error(client):
    """Test that 404 errors are handled"""
    response = client.get('/nonexistent')
    assert response.status_code == 404
