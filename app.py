from flask import Flask, request, jsonify, redirect
from pymongo import MongoClient
from bson.objectid import ObjectId
import hashlib
import datetime
import bcrypt
from itsdangerous import URLSafeTimedSerializer
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
RATE_LIMIT = os.getenv('RATE_LIMIT', '5 per minute')

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
client = MongoClient(MONGO_URI)
db = client['url_shortener']
urls_collection = db['urls']
clicks_collection = db['clicks']
users_collection = db['users']
tokens_collection = db['tokens']

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[RATE_LIMIT]
)

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

        current_time = datetime.datetime.now(datetime.timezone.utc)
        expires_at_aware = token_data['expires_at']
        if expires_at_aware < current_time:
            return None

        return token_data['user_id']
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return None

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
    
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    users_collection.insert_one({
        'username': username,
        'password_hash': hashed_password,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    })

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
@limiter.limit('10 per minute')
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = users_collection.find_one({'username': username})
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash']):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = generate_token(user['_id'])
    return jsonify({'token': token})

@app.route('/api/create', methods=['POST'])
@limiter.limit('10 per minute')
def create_short_url():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401

    data = request.json
    long_url = data.get('long_url')
    
    if not long_url:
        return jsonify({'error': 'long_url is required'}), 400
    
    short_hash = hashlib.md5(long_url.encode()).hexdigest()[:6]
    
    existing_entry = urls_collection.find_one({'short_hash': short_hash})
    if existing_entry:
        return jsonify({'short_url': f'http://luova.link/{short_hash}'})
    
    urls_collection.insert_one({'long_url': long_url, 'short_hash': short_hash, 'user_id': user_id})
    return jsonify({'short_url': f'http://luova.link/{short_hash}'})

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
    
    return jsonify(clicks_list)

@app.route('/admin/users', methods=['GET'])
@limiter.limit('5 per minute')
def admin_get_users():
    # Admin functionality to list users
    users = users_collection.find()
    user_list = list(users)
    return jsonify(user_list)

@app.route('/admin/urls', methods=['GET'])
@limiter.limit('5 per minute')
def admin_get_urls():
    # Admin functionality to list URLs
    urls = urls_collection.find()
    url_list = list(urls)
    return jsonify(url_list)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
