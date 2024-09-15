import requests

class LuovaLinkClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.token = None

    def register(self, username, password):
        url = f"{self.base_url}/api/register"
        data = {
            "username": username,
            "password": password
        }
        response = requests.post(url, json=data)
        if response.status_code == 200 or response.status_code == 201:
            print("User registered successfully.")
        else:
            print(f"Failed to register. Error: {response.json()}")

    def login(self, username, password):
        url = f"{self.base_url}/api/login"
        data = {
            "username": username,
            "password": password
        }
        response = requests.post(url, json=data)
        if response.status_code == 200:
            self.token = response.json().get('token')
            print("Token: ", self.token)
            print("Login successful. Token acquired.")
        else:
            print(f"Login failed. Error: {response.json()}")

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def create_short_url(self, long_url):
        url = f"{self.base_url}/api/create"
        data = {"long_url": long_url}
        response = requests.post(url, json=data, headers=self._headers())
        if response.status_code == 200:
            short_url = response.json().get('short_url')
            print(f"Short URL created: {short_url}")
            return short_url
        else:
            print(f"Failed to create short URL. Error: {response.json()}")

    def get_click_data(self, short_hash):
        url = f"{self.base_url}/api/clicks"
        params = {"short_hash": short_hash}
        response = requests.get(url, headers=self._headers(), params=params)
        if response.status_code == 200:
            click_data = response.json()
            print(f"Click data for {short_hash}: {click_data}")
            return click_data
        else:
            print(f"Failed to retrieve click data. Error: {response.json()}")

# Example usage
if __name__ == "__main__":
    base_url = "http://127.0.0.1:5000"  # Replace with the actual base URL of your API
    client = LuovaLinkClient(base_url)

    # Register a new user
    client.register("new_user", "new_password")

    # Log in to get an API token
    client.login("new_user", "new_password")

    # Create a new short URL
    long_url = "https://example.com"
    short_url = client.create_short_url(long_url)

    # Assuming the short URL is like: "http://luova.link/short_hash"
    short_hash = short_url.split('/')[-1]

    # Get click data for the created short URL
    click_data = client.get_click_data(short_hash)
