import pytest
from flask import json
from app import app, db, users_collection, urls_collection, tokens_collection

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    app.config['MONGO_URI'] = 'mongodb://localhost:27017/'
    with app.test_client() as client:
        yield client

@pytest.fixture
def setup_db():
    # Set up test database
    db.drop_collection('users')
    db.drop_collection('urls')
    db.drop_collection('tokens')
    yield
    # Clean up after tests
    db.drop_collection('users')
    db.drop_collection('urls')
    db.drop_collection('tokens')

def test_register(client, setup_db):
    response = client.post('/api/register', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 201
    assert response.json == {'message': 'User registered successfully'}

def test_login(client, setup_db):
    client.post('/api/register', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    response = client.post('/api/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    assert 'token' in response.json

def test_create_short_url(client, setup_db):
    register_response = client.post('/api/register', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    token = client.post('/api/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    }).json['token']

    response = client.post('/api/create', json={
        'long_url': 'http://example.com'
    }, headers={'Authorization': f'Bearer {token}'})

    assert response.status_code == 200
    assert 'short_url' in response.json

def test_redirect_to_long_url(client, setup_db):
    register_response = client.post('/api/register', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    token = client.post('/api/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    }).json['token']

    create_response = client.post('/api/create', json={
        'long_url': 'http://example.com'
    }, headers={'Authorization': f'Bearer {token}'})
    
    short_url = create_response.json['short_url']
    short_hash = short_url.split('/')[-1]
    
    response = client.get(f'/{short_hash}')
    assert response.status_code == 302  # Redirect status code
    assert response.headers['Location'] == 'http://example.com'

def test_get_clicks(client, setup_db):
    register_response = client.post('/api/register', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    token = client.post('/api/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    }).json['token']

    create_response = client.post('/api/create', json={
        'long_url': 'http://example.com'
    }, headers={'Authorization': f'Bearer {token}'})
    
    short_hash = create_response.json['short_url'].split('/')[-1]
    client.get(f'/{short_hash}')  # Simulate a redirect to record a click
    
    response = client.get('/api/clicks', headers={'Authorization': f'Bearer {token}'}, query_string={'short_hash': short_hash})
    assert response.status_code == 200
    assert len(response.json) > 0

# Admin tests would go here, if you have admin functionality to test.

if __name__ == '__main__':
    pytest.main()
