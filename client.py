import requests

BASE_URL = 'http://localhost:5000'

def register(username, password):
    url = f'{BASE_URL}/api/register'
    payload = {
        'username': username,
        'password': password
    }
    response = requests.post(url, json=payload)
    return response.json()

def login(username, password):
    url = f'{BASE_URL}/api/login'
    payload = {
        'username': username,
        'password': password
    }
    response = requests.post(url, json=payload)
    return response.json()

def create_short_url(token, long_url):
    url = f'{BASE_URL}/api/create'
    headers = {
        'Authorization': f'Bearer {token}'
    }
    payload = {
        'long_url': long_url
    }
    response = requests.post(url, json=payload, headers=headers)
    return response.json()

def get_clicks(token, short_hash):
    url = f'{BASE_URL}/api/clicks'
    headers = {
        'Authorization': f'Bearer {token}'
    }
    params = {
        'short_hash': short_hash
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json()

def admin_get_users():
    url = f'{BASE_URL}/admin/users'
    response = requests.get(url)
    return response.json()

def admin_get_urls():
    url = f'{BASE_URL}/admin/urls'
    response = requests.get(url)
    return response.json()

# Example usage
if __name__ == "__main__":
    # Register a new user
    print(register('testuser21', 'testpassword'))

    # Login the user and get the token
    login_response = login('testuser21', 'testpassword')
    token = login_response.get('token')

    # Create a short URL
    short_url_response = create_short_url(token, 'https://example.com')
    print(short_url_response)

    # Get clicks for a short URL
    short_hash = short_url_response.get('short_url').split('/')[-1]
    print(get_clicks(token, short_hash))

    # Admin functionalities
    print(admin_get_users())
    print(admin_get_urls())
