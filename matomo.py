import requests
import random

class MatomoClient:
    def __init__(self, matomo_url, site_id):
        self.matomo_url = matomo_url
        self.site_id = site_id
    
    def track_event(self, request, category, action, name=None, value=None):
        """
        Track an event using the Matomo HTTP API.

        Parameters
        ----------
        request : flask.Request
            The HTTP request object.
        category : str
            The event category.
        action : str
            The event action.
        name : str, optional
            The event name for the action.
        value : int or float, optional
            The numerical value associated with the event.

        Returns
        -------
        None
        """
        params = {
            'idsite': self.site_id,
            'rec': 1,
            'apiv': 1,
            'action_name': name if name else f"{category} / {action}",
            'url': request.url,
            '_id': '',  # Unique visitor ID; update if available
            'rand': random.randint(1, 1000000),
            'e_c': category,
            'e_a': action,
            'e_n': name or '',
            'e_v': value if value is not None else 0,
        }
        if request.referrer:
            params['urlref'] = request.referrer
        if request.headers.get('User-Agent'):
            params['ua'] = request.headers.get('User-Agent')
        if request.headers.get('Accept-Language'):
            params['lang'] = request.headers.get('Accept-Language')
        
        response = requests.get(self.matomo_url, params=params)
        response.raise_for_status()
