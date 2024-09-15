import requests
import random

class MatomoClient:
    def __init__(self, matomo_url, site_id):
        self.matomo_url = matomo_url
        self.site_id = site_id
    
    def track_event(self, request, category, action, name=None, value=None):
        params = {
            'idsite': self.site_id,
            'rec': 1,
            'action_name': name,
            'url': request.url,
            'e_c': category,
            'e_a': action,
            'e_n': name or '',
            'e_v': value or '',
            'rand': random.random()
        }
        response = requests.get(self.matomo_url, params=params)
        response.raise_for_status()  # Raise an error for bad status codes
