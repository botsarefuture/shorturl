from utils import process_object_ids
from flask import Flask, request, jsonify, redirect, render_template
from pymongo import MongoClient
import hashlib
import datetime
from itsdangerous import URLSafeTimedSerializer
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import logging
from matomo import MatomoClient  # Updated import for Matomo
from passman import PasswordManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://95.216.148.93:27017/')
RATE_LIMIT = os.getenv('RATE_LIMIT', '5 per minute')
MATOMO_URL = os.getenv('MATOMO_URL', 'https://matomo.luova.club/matomo.php')
MATOMO_SITE_ID = os.getenv('MATOMO_SITE_ID', '3')

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
client = MongoClient(MONGO_URI)
db = client['url_shortener']
urls_collection = db['urls']
clicks_collection = db['clicks']
users_collection = db['users']
tokens_collection = db['tokens']
unregistered_users_collection = db['unregistered_users']


serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[RATE_LIMIT],
    storage_uri=MONGO_URI
)

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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
@limiter.limit('10 per minute')
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    existing_user = users_collection.find_one({'username': username})
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409
    
    hashed_password = PasswordManager.hash_password(password)

    users_collection.insert_one({
        'username': username,
        'password_hash': hashed_password,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    })

    # Track user registration with Matomo
    matomo_client.track_event(request,category='User', action='Register', name=username)
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
@limiter.limit('10 per minute')
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = users_collection.find_one({'username': username})
    if not user or not PasswordManager.check_password(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = generate_token(user['_id'])
    
    # Track user login with Matomo
    matomo_client.track_event(request,category='User', action='Login', name=username)
    
    return jsonify({'token': token})
@app.route('/api/create', methods=['POST'])
@limiter.limit('10 per minute')
def create_short_url():
    token = request.headers.get('Authorization')
    if token is not None:
        user_id = verify_token(token)
    else:
        user_id = None
    
    # Get the user's IP address for tracking unregistered users
    user_ip = request.remote_addr

    if user_id:
        # Registered user - no restrictions
        long_url = request.json.get('long_url')
        if not long_url:
            return jsonify({'error': 'long_url is required'}), 400
        
        short_hash = hashlib.md5(long_url.encode()).hexdigest()[:6]
        existing_entry = urls_collection.find_one({'short_hash': short_hash})
        if existing_entry:
            return jsonify({'short_url': f'https://link.luova.club/{short_hash}'})
        
        urls_collection.insert_one({'long_url': long_url, 'short_hash': short_hash, 'user_id': user_id})

        # Track URL creation with Matomo
        matomo_client.track_event(request, category='URL', action='Create', name=short_hash)
        
        return jsonify({'short_url': f'https://link.luova.club/{short_hash}'})
    
    # For unregistered users
    today = datetime.datetime.now(datetime.timezone.utc).date()  # Use date part of datetime
    daily_limit = 3
    
    # Convert the date to datetime at midnight for storage and comparison
    today_start = datetime.datetime.combine(today, datetime.time.min)
    
    # Check if this IP has created URLs today
    count_entry = unregistered_users_collection.find_one({
        'ip_address': user_ip,
        'date': today_start  # Use datetime for query
    })
    
    if count_entry:
        if count_entry['count'] >= daily_limit:
            return jsonify({'error': 'Daily limit of 3 URLs exceeded'}), 403
        else:
            unregistered_users_collection.update_one(
                {'_id': count_entry['_id']},
                {'$inc': {'count': 1}}
            )
    else:
        unregistered_users_collection.insert_one({
            'ip_address': user_ip,
            'date': today_start,  # Use datetime for insertion
            'count': 1
        })
    
    long_url = request.json.get('long_url')
    if not long_url:
        return jsonify({'error': 'long_url is required'}), 400
    
    short_hash = hashlib.md5(long_url.encode()).hexdigest()[:6]
    existing_entry = urls_collection.find_one({'short_hash': short_hash})
    if existing_entry:
        return jsonify({'short_url': f'https://link.luova.club/{short_hash}'})
    
    urls_collection.insert_one({'long_url': long_url, 'short_hash': short_hash, 'ip_address': user_ip})

    # Track URL creation with Matomo
    matomo_client.track_event(request, category='URL', action='Create', name=short_hash)
    
    return jsonify({'short_url': f'https://link.luova.club/{short_hash}'})



@app.route('/<short_hash>', methods=['GET'])
@limiter.limit('100 per minute')
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
@limiter.limit('10 per minute')
def get_clicks():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401

    short_hash = request.args.get('short_hash')
    if not short_hash:
        return jsonify({'error': 'short_hash is required'}), 400
    
    clicks = clicks_collection.find({'short_hash': short_hash, 'user_id': user_id})
    clicks_list = list(clicks)
    
    return jsonify(process_object_ids(clicks_list))

@app.route('/admin/users', methods=['GET'])
@limiter.limit('5 per minute')
def admin_get_users():
    # Admin functionality to list users
    users = users_collection.find()
    user_list = list(users)
    
    # Track admin action with Matomo
    matomo_client.track_event(request,category='Admin', action='Get Users')
    
    return jsonify(process_object_ids(user_list))

@app.route('/admin/urls', methods=['GET'])
@limiter.limit('5 per minute')
def admin_get_urls():
    # Admin functionality to list URLs
    urls = urls_collection.find()
    url_list = list(urls)
    
    # Track admin action with Matomo
    matomo_client.track_event(request,category='Admin', action='Get URLs')
    
    return jsonify(process_object_ids(url_list))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
