"""
Test cases for the Flask application
"""
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
    assert data['service'] == 'Email Analyzer API'


def test_cors_headers(client):
    """Test that CORS headers are set correctly"""
    response = client.options('/api/analyze')
    assert response.status_code == 200
    assert 'Access-Control-Allow-Origin' in response.headers


def test_404_error(client):
    """Test that 404 errors are handled"""
    response = client.get('/nonexistent')
    assert response.status_code == 404


def test_404_returns_json(client):
    response = client.get('/nonexistent')
    payload = response.get_json()
    assert payload is not None
    assert payload['error'] == 'Not found'


def test_405_returns_json(client):
    response = client.delete('/health')
    assert response.status_code == 405
    payload = response.get_json()
    assert payload is not None
    assert payload['error'] == 'Method not allowed'


def test_413_returns_json(app, client):
    app.config['MAX_CONTENT_LENGTH'] = 1024
    response = client.post(
        '/api/analyze',
        data={'emailfile': (__import__('io').BytesIO(b'x' * 4096), 'big.eml')},
        content_type='multipart/form-data',
    )
    assert response.status_code == 413
    payload = response.get_json()
    assert payload is not None
    assert payload['error'] == 'File too large'

