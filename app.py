from utils import process_object_ids
from flask import Flask, abort, request, jsonify, redirect, render_template

from DatabaseManager import DatabaseManager

import hashlib
import datetime
from itsdangerous import URLSafeTimedSerializer
import os
import logging
from matomo import MatomoClient  # Updated import for Matomo

from flask_lac import AuthPackage, login_required, current_user
from flask_lac.user import role_required
import random
from config import Config
import string

from flask_autosec import FlaskAutoSec

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')
MONGO_URI = os.getenv('MONGO_URI', Config.MONGO_URI)
RATE_LIMIT = os.getenv('RATE_LIMIT', '5 per minute')
MATOMO_URL = os.getenv('MATOMO_URL', 'https://matomo.luova.club/matomo.php')
MATOMO_SITE_ID = os.getenv('MATOMO_SITE_ID', '7')



app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

sec = FlaskAutoSec(True)

sec.init_app(app)


client = DatabaseManager().get_instance(Config)
db = client.get_db()

urls_collection = db['urls']
clicks_collection = db['clicks']
users_collection = db['users']
tokens_collection = db['tokens']
unregistered_users_collection = db['unregistered_users']

# Initialize the authentication package
auth_package = AuthPackage(app, app_id="67da6a5df14ba9204442dec9")


serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize Matomo tracker
matomo_client = MatomoClient(MATOMO_URL, MATOMO_SITE_ID)

def generate_token(user_id):
    token = serializer.dumps(str(user_id), salt='api-token')
    current_time = datetime.datetime.now(datetime.timezone.utc)
    tokens_collection.insert_one({
        'user_id': str(user_id),
        'token': token,
        'created_at': current_time,
        'expires_at': current_time + datetime.timedelta(days=30)
    })
    return token

def verify_token(token):
    token = token.replace("Bearer ", "")
    try:
        user_id = serializer.loads(token, salt='api-token', max_age=30*24*60*60)
        token_data = tokens_collection.find_one({'user_id': user_id, 'token': token})
        if not token_data:
            return None

        current_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        expires_at_aware = token_data['expires_at']
        print(current_time, expires_at_aware)
        if expires_at_aware < current_time:
            return None

        return token_data['user_id']
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return None

@app.route("/home/")
def index():
    # user has logged out, so render a page that says they have logged out, and provide a link to the login page
    return render_template("home.html")

@app.route('/')
@login_required
def home():
    print(current_user._info)
    return render_template('index.html')

@app.route('/api/create', methods=['POST'])
@login_required
def create_short_url():
    # Get the user's IP address for tracking and the authenticated user's ID
    user_ip = request.remote_addr
    user_id = current_user._info['_id']
    
    if not current_user:
        print('Unauthorized: current_user not authenticated')
        abort(401, description='Unauthorized: current_user not authenticated')
        return ''

    # Registered user - no restrictions
    long_url = request.json.get('long_url')
    if not long_url:
        return jsonify({'error': 'long_url is required'}), 400
    
    while True:
        random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
        short_hash = hashlib.md5(f"{long_url}{random_str}".encode()).hexdigest()[:6]
        if not urls_collection.find_one({'short_hash': short_hash}):
            break
        
    # Refactored URL document creation for clarity and consistency
    user_info = {'user_id': user_id, 'ip_address': user_ip}
    url_data = {'long_url': long_url, 'short_hash': short_hash, 'user': user_info}
    urls_collection.insert_one(url_data)

    # Track URL creation with Matomo in a professional manner
    matomo_client.track_event(request, category='URL', action='Create', name=short_hash)
    
    return jsonify({'short_url': f'https://link.luova.club/{short_hash}'})

@app.route("/dashboard")
@login_required
def dashboard():
    """
    Render the user's dashboard with URLs and their corresponding click counts.

    Returns
    -------
    str
        HTML content rendered for the dashboard.
    """
    user_id = current_user._info['_id']
    urls = urls_collection.find({'user.user_id': user_id})
    updated_urls = []
    for url in urls:
        # Count clicks for each URL by its short_hash
        clicks_count = clicks_collection.count_documents({'short_hash': url['short_hash']})
        url['clicks_count'] = clicks_count
        updated_urls.append(url)
        
    return render_template('dashboard.html', urls=process_object_ids(updated_urls))

@app.route("/api/my-urls")
@login_required
def my_urls():
    user_id = current_user._info['_id']
    urls = urls_collection.find({'user.user_id': user_id})
    url_list = list(urls)
    return jsonify(process_object_ids(url_list))


@app.route('/<short_hash>', methods=['GET'])
def redirect_to_long_url(short_hash):
    entry = urls_collection.find_one({'short_hash': short_hash})
    
    if entry:
        clicks_collection.insert_one({
            'short_hash': short_hash,
            'timestamp': datetime.datetime.now(datetime.timezone.utc),
            'user_agent': request.headers.get('User-Agent'),
            'ip_address': request.remote_addr
        })
        
        # Track URL redirection with Matomo
        matomo_client.track_event(request,category='URL', action='Redirect', name=short_hash)
        
        return redirect(entry['long_url'])
    
    return jsonify({'error': 'URL not found'}), 404

@app.route('/api/clicks', methods=['GET'])
@login_required
def get_clicks():
    """
    Retrieve clicks for the specified short hash for the authenticated user.
    
    Parameters
    ----------
    None
    
    Returns
    -------
    flask.Response
        JSON response containing the list of clicks or an error message.
    """
    user_id = current_user._info['_id']
    short_hash = request.args.get('short_hash')
    if not short_hash:
        return jsonify({'error': 'short_hash is required'}), 400

    clicks = clicks_collection.find({'short_hash': short_hash, 'user_id': user_id})
    clicks_list = list(clicks)
    
    return jsonify(process_object_ids(clicks_list))

@app.route('/admin/urls', methods=['GET'])
@login_required
@role_required(10)
def admin_get_urls():
    # Admin functionality to list URLs
    urls = urls_collection.find()
    url_list = list(urls)
    
    # Track admin action with Matomo
    matomo_client.track_event(request,category='Admin', action='Get URLs')
    
    return jsonify(process_object_ids(url_list))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
