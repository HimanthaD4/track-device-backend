from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit, join_room
import pymongo
from bson.objectid import ObjectId
import os
from dotenv import load_dotenv
import jwt
import datetime
import platform
import hashlib
import math
import threading
import time
import urllib.parse
import traceback
import re

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['CORS_HEADERS'] = 'Content-Type,Authorization'

CORS(app, 
     resources={r"/*": {"origins": "*"}},
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-Device-ID"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=1e8,
    transports=['websocket', 'polling'],
    logger=True,
    engineio_logger=True
)

bcrypt = Bcrypt(app)

MONGO_URI = os.getenv("MONGO_URI")
client = pymongo.MongoClient(
    MONGO_URI,
    maxPoolSize=50,
    minPoolSize=10,
    connectTimeoutMS=30000,
    socketTimeoutMS=30000,
    serverSelectionTimeoutMS=30000,
    retryWrites=True,
    w='majority'
)
db = client.tracker_db
users_collection = db.users
devices_collection = db.devices
locations_collection = db.locations
university_collection = db.university

device_connections_collection = db.device_connections
device_locations_collection = db.device_locations_live

try:
    devices_collection.create_index([('device_id', 1)], unique=True, background=True)
    devices_collection.create_index([('user_email', 1)], background=True)
    devices_collection.create_index([('ua_fingerprint', 1)], background=True)
    users_collection.create_index([('email', 1)], unique=True, background=True)
    locations_collection.create_index([('device_id', 1)], background=True)
    locations_collection.create_index([('timestamp', -1)], background=True)
    locations_collection.create_index([('user_email', 1)], background=True)
    device_connections_collection.create_index([('device_id', 1)], unique=True, background=True)
    device_connections_collection.create_index([('user_email', 1)], background=True)
    device_locations_collection.create_index([('device_id', 1)], unique=True, background=True)
    device_locations_collection.create_index([('user_email', 1)], background=True)
except Exception as e:
    print(f"Index creation warning: {e}")

JWT_SECRET = os.getenv("JWT_SECRET", "default_secret_key")

connected_devices = {}
user_devices = {}
device_locations = {}

HIGH_ACCURACY_THRESHOLD = 10.0
MAX_ACCEPTABLE_ACCURACY = 100.0
MAX_POSITION_DRIFT = 10.0

UNIVERSITY_SIZE = 0.000324
SECTION_CONFIGS = [
    {'name': 'Main Building', 'color': '#e74c3c', 'row': 0, 'col': 1},
    {'name': 'Library', 'color': '#3498db', 'row': 0, 'col': 2},
    {'name': 'New Building', 'color': '#2ecc71', 'row': 1, 'col': 0},
    {'name': 'Canteen', 'color': '#f39c12', 'row': 1, 'col': 1},
    {'name': 'Sports Complex', 'color': '#9b59b6', 'row': 1, 'col': 2},
    {'name': 'Admin Block', 'color': '#1abc9c', 'row': 2, 'col': 1}
]

last_location_cache = {}
CACHE_TTL = 2

def normalize_user_agent(user_agent):
    if not user_agent:
        return ""
    normalized = user_agent.lower()
    normalized = re.sub(r'/\d+\.\d+(\.\d+(\.\d+)?)?', '/', normalized)
    normalized = re.sub(r'\([^)]*khtml[^)]*\)', '', normalized)
    normalized = re.sub(r'like gecko', '', normalized)
    normalized = re.sub(r'safari/\d+', 'safari', normalized)
    normalized = ' '.join(normalized.split())
    return normalized

def generate_ua_fingerprint(user_agent):
    if not user_agent:
        return None
    return hashlib.sha256(user_agent.encode('utf-8')).hexdigest()

def find_existing_device_for_user(user_email, device_id, user_agent):
    if not user_email:
        return None, None
    
    existing_device = devices_collection.find_one({
        'device_id': device_id,
        'user_email': user_email
    })
    
    if existing_device:
        return existing_device, 'exact_id'
    
    if user_agent:
        ua_fingerprint = generate_ua_fingerprint(normalize_user_agent(user_agent))
        existing_device = devices_collection.find_one({
            'ua_fingerprint': ua_fingerprint,
            'user_email': user_email
        })
        
        if existing_device:
            return existing_device, 'ua_fingerprint'
    
    return None, None

def migrate_device_history(old_device_id, new_device_id, user_email):
    try:
        locations_result = locations_collection.update_many(
            {'device_id': old_device_id, 'user_email': user_email},
            {'$set': {'device_id': new_device_id}}
        )
        
        device_locations_result = device_locations_collection.update_many(
            {'device_id': old_device_id, 'user_email': user_email},
            {'$set': {'device_id': new_device_id}}
        )
        
        connections_result = device_connections_collection.update_many(
            {'device_id': old_device_id, 'user_email': user_email},
            {'$set': {'device_id': new_device_id}}
        )
        
        users_collection.update_one(
            {'email': user_email},
            {'$pull': {'devices': old_device_id}}
        )
        users_collection.update_one(
            {'email': user_email},
            {'$addToSet': {'devices': new_device_id}}
        )
        
        return True
    except Exception as e:
        print(f"Error migrating device history: {e}")
        return False

def extract_device_id_from_request():
    try:
        device_id = request.args.get('device_id')
        if device_id:
            return device_id
        
        try:
            if hasattr(request, 'environ'):
                query_string = request.environ.get('QUERY_STRING', '')
                if query_string:
                    query_params = urllib.parse.parse_qs(query_string)
                    device_id = query_params.get('device_id', [None])[0]
                    if device_id:
                        return device_id
        except Exception as e:
            print(f"Error parsing QUERY_STRING: {e}")
        
        device_id = request.headers.get('X-Device-ID')
        if device_id:
            return device_id
        
        if hasattr(request, 'auth') and request.auth:
            device_id = request.auth.get('device_id')
            if device_id:
                return device_id
        
        try:
            if hasattr(request, 'environ'):
                auth_data = request.environ.get('socketio.auth', {})
                if isinstance(auth_data, dict):
                    device_id = auth_data.get('device_id')
                    if device_id:
                        return device_id
        except Exception as e:
            print(f"Error extracting from socketio.auth: {e}")
        
        return None
    except Exception as e:
        print(f"Error in extract_device_id_from_request: {e}")
        return None

def validate_device_id(device_id):
    if not device_id:
        return False
    if device_id == 'null' or device_id == 'undefined' or device_id == 'None':
        return False
    if len(device_id) < 5:
        return False
    return True

def generate_university_layout(center_lat, center_lon):
    sections = []
    section_size = UNIVERSITY_SIZE / 3
    start_lat = center_lat + UNIVERSITY_SIZE / 2
    start_lon = center_lon - UNIVERSITY_SIZE / 2
    
    for section_config in SECTION_CONFIGS:
        row = section_config['row']
        col = section_config['col']
        min_lat = start_lat - (row + 1) * section_size
        max_lat = start_lat - row * section_size
        min_lon = start_lon + col * section_size
        max_lon = start_lon + (col + 1) * section_size
        
        section = {
            'name': section_config['name'],
            'color': section_config['color'],
            'bounds': {
                'min_lat': min_lat,
                'max_lat': max_lat,
                'min_lon': min_lon,
                'max_lon': max_lon
            },
            'center': {
                'lat': (min_lat + max_lat) / 2,
                'lon': (min_lon + max_lon) / 2
            },
            'size_meters': 12.0
        }
        sections.append(section)
    
    return sections

def detect_section(latitude, longitude, sections):
    for section in sections:
        bounds = section['bounds']
        if (bounds['min_lat'] <= latitude <= bounds['max_lat'] and
            bounds['min_lon'] <= longitude <= bounds['max_lon']):
            return section['name']
    return 'Outside Campus'

def detect_os(user_agent):
    if not user_agent:
        return 'Unknown'
    user_agent = user_agent.lower()
    if 'iphone' in user_agent or 'ipad' in user_agent or 'ipod' in user_agent:
        return 'iPhone'
    elif 'android' in user_agent:
        return 'Android'
    elif 'mac' in user_agent or 'macintosh' in user_agent:
        return 'Mac'
    elif 'windows' in user_agent:
        return 'Windows'
    system = platform.system()
    if system == 'Darwin':
        return 'Mac'
    elif system == 'Windows':
        return 'Windows'
    elif system == 'Linux':
        if 'android' in user_agent:
            return 'Android'
        else:
            return 'Unknown'
    else:
        return 'Unknown'

def detect_browser(user_agent):
    if not user_agent:
        return 'Unknown'
    user_agent = user_agent.lower()
    if 'chrome' in user_agent and 'edg' not in user_agent:
        return 'Chrome'
    elif 'safari' in user_agent and 'chrome' not in user_agent:
        return 'Safari'
    elif 'firefox' in user_agent:
        return 'Firefox'
    elif 'edge' in user_agent or 'edg' in user_agent:
        return 'Edge'
    elif 'opera' in user_agent or 'opr' in user_agent:
        return 'Opera'
    else:
        return 'Unknown'

def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371000
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    a = math.sin(delta_phi/2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    distance = R * c
    return distance

def constrain_location_to_radius(new_lat, new_lon, anchor_lat, anchor_lon, max_radius):
    distance = calculate_distance(anchor_lat, anchor_lon, new_lat, new_lon)
    if distance <= max_radius:
        return new_lat, new_lon, distance
    phi1 = math.radians(anchor_lat)
    phi2 = math.radians(new_lat)
    lambda1 = math.radians(anchor_lon)
    lambda2 = math.radians(new_lon)
    y = math.sin(lambda2 - lambda1) * math.cos(phi2)
    x = math.cos(phi1) * math.sin(phi2) - math.sin(phi1) * math.cos(phi2) * math.cos(lambda2 - lambda1)
    bearing = math.atan2(y, x)
    R = 6371000
    angular_distance = max_radius / R
    constrained_lat = math.asin(
        math.sin(phi1) * math.cos(angular_distance) +
        math.cos(phi1) * math.sin(angular_distance) * math.cos(bearing)
    )
    constrained_lon = lambda1 + math.atan2(
        math.sin(bearing) * math.sin(angular_distance) * math.cos(phi1),
        math.cos(angular_distance) - math.sin(phi1) * math.sin(constrained_lat)
    )
    constrained_lat = math.degrees(constrained_lat)
    constrained_lon = math.degrees(constrained_lon)
    return constrained_lat, constrained_lon, distance

def validate_and_constrain_location(device_id, latitude, longitude, accuracy):
    if not validate_device_id(device_id):
        return None, None, None, False, "invalid_device_id"
    
    if accuracy > MAX_ACCEPTABLE_ACCURACY:
        print(f"WARNING: Device {device_id[:8]}... accuracy {accuracy:.1f}m")
    
    last_location = locations_collection.find_one(
        {'device_id': device_id}, 
        sort=[('timestamp', -1)]
    )
    
    if accuracy < HIGH_ACCURACY_THRESHOLD:
        return latitude, longitude, accuracy, True, "high_accuracy_accepted"
    
    if last_location and 'latitude' in last_location and 'longitude' in last_location:
        anchor_lat = last_location['latitude']
        anchor_lon = last_location['longitude']
        distance = calculate_distance(anchor_lat, anchor_lon, latitude, longitude)
        
        if distance > MAX_POSITION_DRIFT:
            constrained_lat, constrained_lon, actual_distance = constrain_location_to_radius(
                latitude, longitude, anchor_lat, anchor_lon, MAX_POSITION_DRIFT
            )
            return constrained_lat, constrained_lon, accuracy, True, "constrained_to_radius"
        else:
            return latitude, longitude, accuracy, True, "within_drift_limit"
    else:
        return latitude, longitude, accuracy, True, "first_location_accepted"

def token_required(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_user = users_collection.find_one({'email': data['email']})
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({'error': f'Token validation failed: {str(e)}'}), 401
        return f(current_user, *args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def serialize_document(document):
    if document is None:
        return None
    if '_id' in document:
        document['_id'] = str(document['_id'])
    for key, value in document.items():
        if isinstance(value, datetime.datetime):
            document[key] = value.isoformat()
        elif isinstance(value, ObjectId):
            document[key] = str(value)
    return document

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With,X-Socket-ID,X-Device-ID')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Max-Age', '86400')
    return response

@socketio.on('connect')
def handle_connect():
    try:
        device_id = extract_device_id_from_request()
        
        if device_id and validate_device_id(device_id):
            device_connections_collection.update_one(
                {'device_id': device_id},
                {
                    '$set': {
                        'socket_id': request.sid,
                        'device_id': device_id,
                        'connected_at': datetime.datetime.utcnow(),
                        'is_online': True,
                        'last_ping': datetime.datetime.utcnow()
                    }
                },
                upsert=True
            )
        
        emit('connected', {
            'message': 'Connected to server',
            'sid': request.sid,
            'device_id': device_id,
            'status': 'ready_for_join'
        })
        
    except Exception as e:
        print(f'Connect error: {e}')
        emit('connection_error', {'message': str(e)})

@socketio.on('disconnect')
def handle_disconnect():
    try:
        connection = device_connections_collection.find_one({'socket_id': request.sid})
        if connection:
            device_id = connection['device_id']
            user_email = connection.get('user_email')
            
            device_connections_collection.delete_one({'socket_id': request.sid})
            
            if device_id:
                device_locations_collection.update_one(
                    {'device_id': device_id},
                    {'$set': {'is_online': False, 'last_seen': datetime.datetime.utcnow()}},
                    upsert=True
                )
            
            if device_id in connected_devices:
                del connected_devices[device_id]
            
            if user_email and user_email in user_devices and device_id in user_devices[user_email]:
                user_devices[user_email].remove(device_id)
            
            if user_email:
                try:
                    socketio.emit('device_offline', {
                        'device_id': device_id,
                        'timestamp': datetime.datetime.utcnow().isoformat()
                    }, room=user_email)
                except Exception as e:
                    print(f"Could not emit device offline: {e}")
                
    except Exception as e:
        print(f"Error cleaning up device connection: {e}")

@socketio.on_error()
def handle_error(e):
    print(f'Socket.IO error: {e}')

@socketio.on('join_room')
def handle_join_room(data):
    try:
        user_email = data.get('user_email')
        device_id = data.get('device_id')
        token = data.get('token')
        
        if not device_id or device_id == 'null':
            connection = device_connections_collection.find_one({'socket_id': request.sid})
            if connection:
                device_id = connection.get('device_id')
        
        if not device_id or device_id == 'null':
            emit('join_error', {
                'message': 'Device ID required. Please reconnect or refresh.',
                'code': 'DEVICE_ID_MISSING'
            })
            return
        
        if not validate_device_id(device_id):
            emit('join_error', {
                'message': 'Invalid Device ID format',
                'code': 'DEVICE_ID_INVALID'
            })
            return
        
        if not user_email:
            emit('join_error', {'message': 'User email required'})
            return
        
        if token:
            try:
                if token.startswith('Bearer '):
                    token = token.split(' ')[1]
                jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            except Exception as e:
                emit('join_error', {'message': 'Invalid token'})
                return
        
        device_exists = devices_collection.find_one({'device_id': device_id})
        
        if not device_exists:
            emit('join_error', {
                'message': 'Device not registered. Please add device first.',
                'code': 'DEVICE_NOT_REGISTERED',
                'device_id': device_id
            })
            return
        
        if device_exists['user_email'] != user_email:
            emit('join_error', {
                'message': 'Device registered to another account',
                'code': 'DEVICE_WRONG_USER'
            })
            return
        
        device_connections_collection.update_one(
            {'device_id': device_id},
            {
                '$set': {
                    'socket_id': request.sid,
                    'user_email': user_email,
                    'device_id': device_id,
                    'connected_at': datetime.datetime.utcnow(),
                    'is_online': True,
                    'last_ping': datetime.datetime.utcnow()
                }
            },
            upsert=True
        )
        
        connected_devices[device_id] = request.sid
        
        if user_email not in user_devices:
            user_devices[user_email] = set()
        user_devices[user_email].add(device_id)
        
        join_room(user_email)
        
        device_info = devices_collection.find_one({'device_id': device_id})
        device_name = device_info.get('device_name', 'Unknown Device') if device_info else 'Unknown Device'
        device_os = device_info.get('os', 'Unknown') if device_info else 'Unknown'
        
        device_locations_collection.update_one(
            {'device_id': device_id},
            {
                '$set': {
                    'device_id': device_id,
                    'device_name': device_name,
                    'os': device_os,
                    'user_email': user_email,
                    'is_online': True,
                    'socket_id': request.sid,
                    'last_seen': datetime.datetime.utcnow(),
                    'connected_at': datetime.datetime.utcnow()
                }
            },
            upsert=True
        )
        
        emit('join_confirmation', {
            'message': f'Joined room for {user_email}',
            'user_email': user_email,
            'device_id': device_id,
            'device_name': device_name,
            'device_os': device_os
        })
        
        try:
            user = users_collection.find_one({'email': user_email})
            if user and 'devices' in user:
                for dev_id in user['devices']:
                    if not validate_device_id(dev_id):
                        continue
                    
                    location = device_locations_collection.find_one(
                        {'device_id': dev_id},
                        {'_id': 0}
                    )
                    
                    if not location:
                        location = locations_collection.find_one(
                            {'device_id': dev_id},
                            sort=[('timestamp', -1)]
                        )
                    
                    if location:
                        device_info = devices_collection.find_one({'device_id': dev_id})
                        device_name = device_info.get('device_name', 'Unknown') if device_info else 'Unknown'
                        device_os = device_info.get('os', 'Unknown') if device_info else 'Unknown'
                        
                        is_online = dev_id in connected_devices
                        
                        broadcast_data = {
                            'device_id': dev_id,
                            'device_name': device_name,
                            'os': device_os,
                            'latitude': location.get('latitude', 0),
                            'longitude': location.get('longitude', 0),
                            'accuracy': location.get('accuracy', 0),
                            'timestamp': location.get('timestamp', datetime.datetime.utcnow()).isoformat(),
                            'validation_reason': location.get('validation_reason', 'initial'),
                            'current_section': location.get('current_section', 'Outside Campus'),
                            'is_online': is_online
                        }
                        
                        socketio.emit('location_update', broadcast_data, room=user_email)
            
        except Exception as e:
            print(f"Error sending initial locations: {e}")
        
        try:
            socketio.emit('device_connected', {
                'device_id': device_id,
                'device_name': device_name,
                'os': device_os,
                'timestamp': datetime.datetime.utcnow().isoformat()
            }, room=user_email)
        except Exception as e:
            print(f"Could not emit device connected: {e}")
            
    except Exception as e:
        print(f"Error in join_room: {str(e)}")
        emit('join_error', {'message': str(e)})

@socketio.on('update_location')
def handle_location_update(data):
    try:
        device_id = data.get('device_id')
        user_email = data.get('user_email')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        accuracy = data.get('accuracy', 0)
        
        if not device_id or device_id == 'null':
            connection = device_connections_collection.find_one({'socket_id': request.sid})
            if connection:
                device_id = connection.get('device_id')
                user_email = connection.get('user_email', user_email)
        
        if not all([device_id, user_email, latitude, longitude]):
            emit('location_error', {'message': 'Missing required fields'})
            return
        
        if not validate_device_id(device_id):
            emit('location_error', {'message': 'Invalid Device ID'})
            return
        
        try:
            raw_lat = float(latitude)
            raw_lng = float(longitude)
            acc = float(accuracy)
        except ValueError as e:
            return
        
        validated_lat, validated_lng, validated_acc, is_valid, reason = validate_and_constrain_location(
            device_id, raw_lat, raw_lng, acc
        )
        
        if not is_valid:
            try:
                socketio.emit('location_rejected', {
                    'device_id': device_id,
                    'reason': reason,
                    'original_accuracy': acc
                }, room=user_email)
            except Exception as e:
                print(f"Could not emit location rejected: {e}")
            return
        
        current_time = datetime.datetime.utcnow()
        
        device_info = devices_collection.find_one({'device_id': device_id})
        device_name = device_info.get('device_name', 'Unknown Device') if device_info else 'Unknown Device'
        device_os = device_info.get('os', 'Unknown') if device_info else 'Unknown'
        
        university_data = university_collection.find_one({'user_email': user_email})
        current_section = 'Outside Campus'
        if university_data and 'sections' in university_data:
            current_section = detect_section(validated_lat, validated_lng, university_data['sections'])
        
        location_data = {
            'device_id': device_id,
            'latitude': validated_lat,
            'longitude': validated_lng,
            'accuracy': validated_acc,
            'timestamp': current_time,
            'user_email': user_email,
            'validation_reason': reason,
            'current_section': current_section,
            'raw_latitude': raw_lat,
            'raw_longitude': raw_lng,
            'raw_accuracy': acc
        }
        
        locations_collection.insert_one(location_data)
        
        device_locations_collection.update_one(
            {'device_id': device_id},
            {
                '$set': {
                    'device_id': device_id,
                    'device_name': device_name,
                    'os': device_os,
                    'latitude': validated_lat,
                    'longitude': validated_lng,
                    'accuracy': validated_acc,
                    'user_email': user_email,
                    'current_section': current_section,
                    'timestamp': current_time,
                    'is_online': True,
                    'last_seen': current_time
                }
            },
            upsert=True
        )
        
        devices_collection.update_one(
            {'device_id': device_id},
            {'$set': {
                'last_seen': current_time,
                'location_tracking': True,
                'last_latitude': validated_lat,
                'last_longitude': validated_lng,
                'last_accuracy': validated_acc,
                'current_section': current_section
            }}
        )
        
        broadcast_data = {
            'device_id': device_id,
            'device_name': device_name,
            'os': device_os,
            'latitude': validated_lat,
            'longitude': validated_lng,
            'accuracy': validated_acc,
            'timestamp': current_time.isoformat(),
            'validation_reason': reason,
            'current_section': current_section,
            'is_online': True
        }
        
        try:
            socketio.emit('location_update', broadcast_data, room=user_email)
        except Exception as e:
            print(f"Could not emit location update: {e}")
        
    except Exception as e:
        print(f"Error in update_location: {str(e)}")

@app.route('/')
def home():
    return jsonify({'message': 'Tracker API is running', 'status': 'online', 'timestamp': datetime.datetime.utcnow().isoformat()})

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        client.admin.command('ping')
        connected_count = len(connected_devices)
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'database': 'connected',
            'connected_devices': connected_count,
            'server': 'running',
            'version': '1.0.0',
            'websocket_support': True,
            'device_id_fix': 'APPLIED'
        }), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        if users_collection.find_one({'email': email}):
            return jsonify({'error': 'User already exists'}), 400
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        user = {
            'email': email,
            'password': hashed_password,
            'created_at': datetime.datetime.utcnow(),
            'devices': [],
            'location_permission': False,
            'last_login': datetime.datetime.utcnow()
        }
        
        result = users_collection.insert_one(user)
        user['_id'] = str(result.inserted_id)
        
        token = jwt.encode({
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }, JWT_SECRET)
        
        user.pop('password', None)
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': serialize_document(user)
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = users_collection.find_one({'email': email})
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not bcrypt.check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        token = jwt.encode({
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }, JWT_SECRET)
        
        users_collection.update_one(
            {'email': email},
            {'$set': {'last_login': datetime.datetime.utcnow()}}
        )
        
        user_data = serialize_document(user)
        user_data.pop('password', None)
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': user_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-device', methods=['GET'])
@token_required
def check_device(current_user):
    try:
        device_id = request.headers.get('X-Device-ID') or request.args.get('device_id')
        user_agent = request.headers.get('User-Agent', '')
        
        if not device_id:
            system_info = f"{platform.system()}{platform.release()}{platform.machine()}"
            fingerprint_string = system_info + user_agent
            device_id = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        
        existing_device, match_type = find_existing_device_for_user(
            current_user['email'], 
            device_id, 
            user_agent
        )
        
        device_status = 'not_registered'
        device_owner = None
        needs_migration = False
        old_device_id = None
        
        if existing_device:
            if match_type == 'exact_id':
                device_status = 'registered_to_me'
                device_owner = current_user['email']
            elif match_type == 'ua_fingerprint':
                device_status = 'needs_migration'
                device_owner = current_user['email']
                needs_migration = True
                old_device_id = existing_device['device_id']
        else:
            device = devices_collection.find_one({'device_id': device_id})
            if device:
                if device['user_email'] == current_user['email']:
                    device_status = 'registered_to_me'
                    device_owner = current_user['email']
                else:
                    device_status = 'registered_to_other'
                    device_owner = device['user_email']
        
        user = users_collection.find_one({'email': current_user['email']})
        user_has_device = False
        if user and 'devices' in user:
            for dev_id in user['devices']:
                if dev_id == device_id:
                    user_has_device = True
                    break
        
        os = detect_os(user_agent)
        
        response = {
            'device_id': device_id,
            'device_exists': existing_device is not None,
            'user_has_device': user_has_device,
            'device_status': device_status,
            'device_owner': device_owner,
            'os': os,
            'location_permission': user.get('location_permission', False) if user else False
        }
        
        if needs_migration:
            response['needs_migration'] = True
            response['old_device_id'] = old_device_id
            response['new_device_id'] = device_id
            response['message'] = 'Device detected but needs to update device ID'
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/add-device', methods=['POST'])
@token_required
def add_device(current_user):
    try:
        data = request.json
        device_id = data.get('device_id')
        device_name = data.get('device_name', 'My Device')
        
        if not device_id or not validate_device_id(device_id):
            return jsonify({'error': 'Valid Device ID is required'}), 400
        
        user_agent = request.headers.get('User-Agent', 'Unknown')
        normalized_ua = normalize_user_agent(user_agent)
        ua_fingerprint = generate_ua_fingerprint(normalized_ua)
        
        user = users_collection.find_one({'email': current_user['email']})
        user_has_device = False
        if user and 'devices' in user:
            for dev_id in user['devices']:
                if dev_id == device_id:
                    user_has_device = True
                    break
        
        existing_device_exact = devices_collection.find_one({
            'device_id': device_id,
            'user_email': current_user['email']
        })
        
        if existing_device_exact:
            return jsonify({
                'message': 'Device already registered to your account',
                'device': serialize_document(existing_device_exact),
                'already_exists': True,
                'device_status': 'registered_to_me'
            }), 200
        
        device_other_user = devices_collection.find_one({
            'device_id': device_id,
            'user_email': {'$ne': current_user['email']}
        })
        
        if device_other_user:
            return jsonify({
                'error': 'Device already registered to another account',
                'owner': device_other_user['user_email']
            }), 400
        
        existing_device_ua = devices_collection.find_one({
            'ua_fingerprint': ua_fingerprint,
            'user_email': current_user['email']
        })
        
        migration_performed = False
        old_device_id = None
        
        if existing_device_ua:
            old_device_id = existing_device_ua['device_id']
            
            update_result = devices_collection.update_one(
                {'device_id': old_device_id, 'user_email': current_user['email']},
                {'$set': {
                    'device_id': device_id,
                    'last_seen': datetime.datetime.utcnow(),
                    'ua_fingerprint': ua_fingerprint
                }}
            )
            
            if update_result.modified_count > 0:
                migration_success = migrate_device_history(old_device_id, device_id, current_user['email'])
                
                if migration_success:
                    users_collection.update_one(
                        {'email': current_user['email']},
                        {'$pull': {'devices': old_device_id}}
                    )
                    users_collection.update_one(
                        {'email': current_user['email']},
                        {'$addToSet': {'devices': device_id}}
                    )
                    
                    migration_performed = True
        
        if not migration_performed:
            os = detect_os(user_agent)
            browser = detect_browser(user_agent)
            
            device = {
                'device_id': device_id,
                'device_name': device_name,
                'user_email': current_user['email'],
                'added_at': datetime.datetime.utcnow(),
                'os': os,
                'browser': browser,
                'user_agent': user_agent,
                'ua_fingerprint': ua_fingerprint,
                'last_seen': datetime.datetime.utcnow(),
                'location_tracking': False,
                'current_section': 'Outside Campus'
            }
            
            result = devices_collection.insert_one(device)
            device['_id'] = str(result.inserted_id)
            
            users_collection.update_one(
                {'email': current_user['email']},
                {'$addToSet': {'devices': device_id}}
            )
        
        updated_device = devices_collection.find_one({
            'device_id': device_id,
            'user_email': current_user['email']
        })
        
        updated_user = users_collection.find_one({'email': current_user['email']})
        device_count = len(updated_user.get('devices', []))
        
        ml_training_started = False
        if device_count >= 2:
            ml_training_started = True
        
        device_status = {
            'device_id': device_id,
            'device_exists': True,
            'user_has_device': True,
            'device_status': 'registered_to_me',
            'device_owner': current_user['email'],
            'os': detect_os(user_agent)
        }
        
        response = {
            'message': 'Device added successfully',
            'device': serialize_document(updated_device),
            'device_status': device_status,
            'ml_training_started': ml_training_started,
            'device_count': device_count
        }
        
        if migration_performed:
            response['migration_performed'] = True
            response['old_device_id'] = old_device_id
            response['message'] = 'Device migrated successfully to new ID'
        
        return jsonify(response), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user-devices', methods=['GET'])
@token_required
def get_user_devices(current_user):
    try:
        user = users_collection.find_one(
            {'email': current_user['email']},
            {'devices': 1, '_id': 0}
        )
        
        if not user:
            return jsonify({'devices': []}), 200
        
        device_ids = user.get('devices', [])
        
        if not device_ids:
            return jsonify({'devices': []}), 200
        
        devices_cursor = devices_collection.find(
            {'device_id': {'$in': device_ids}},
            {
                'device_id': 1,
                'device_name': 1,
                'os': 1,
                'location_tracking': 1,
                'last_seen': 1,
                'current_section': 1,
                '_id': 0
            }
        )
        
        devices = list(devices_cursor)
        
        for device in devices:
            device_location = device_locations_collection.find_one(
                {'device_id': device['device_id']}
            )
            if device_location:
                device['is_online'] = device_location.get('is_online', False)
                device['last_location_time'] = device_location.get('timestamp')
            else:
                device['is_online'] = False
        
        return jsonify({'devices': devices}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/grant-location-permission', methods=['POST'])
@token_required
def grant_location_permission(current_user):
    try:
        data = request.json
        device_id = data.get('device_id')
        initial_latitude = data.get('latitude')
        initial_longitude = data.get('longitude')
        
        if not device_id:
            return jsonify({'error': 'Device ID is required'}), 400
        
        device = devices_collection.find_one({
            'device_id': device_id,
            'user_email': current_user['email']
        })
        
        if not device:
            return jsonify({'error': 'Device not found or not authorized'}), 404
        
        university_exists = university_collection.find_one({'user_email': current_user['email']})
        
        if not university_exists and initial_latitude and initial_longitude:
            try:
                center_lat = float(initial_latitude)
                center_lon = float(initial_longitude)
                
                sections = generate_university_layout(center_lat, center_lon)
                
                university_data = {
                    'user_email': current_user['email'],
                    'center': {
                        'lat': center_lat,
                        'lon': center_lon
                    },
                    'sections': sections,
                    'created_at': datetime.datetime.utcnow(),
                    'total_size_meters': UNIVERSITY_SIZE * 111000
                }
                
                university_collection.insert_one(university_data)
            except ValueError:
                return jsonify({'error': 'Invalid coordinates'}), 400
        
        users_collection.update_one(
            {'email': current_user['email']},
            {'$set': {'location_permission': True}}
        )
        
        devices_collection.update_one(
            {'device_id': device_id},
            {'$set': {'location_tracking': True}}
        )
        
        university_data = university_collection.find_one({'user_email': current_user['email']})
        
        return jsonify({
            'message': 'Location permission granted successfully',
            'location_permission': True,
            'device_id': device_id,
            'university': serialize_document(university_data) if university_data else None
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/university-layout', methods=['GET'])
@token_required
def get_university_layout(current_user):
    try:
        university_data = university_collection.find_one({'user_email': current_user['email']})
        
        if not university_data:
            return jsonify({'university': None}), 200
        
        return jsonify({
            'university': serialize_document(university_data)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/all-devices-locations', methods=['GET'])
@token_required
def get_all_devices_locations(current_user):
    try:
        user_devices_cursor = device_locations_collection.find(
            {'user_email': current_user['email']},
            {'_id': 0}
        ).sort('timestamp', -1)
        
        all_locations = []
        current_time = datetime.datetime.utcnow()
        
        for location in user_devices_cursor:
            location_time = location.get('timestamp', current_time)
            if isinstance(location_time, str):
                try:
                    location_time = datetime.datetime.fromisoformat(location_time.replace('Z', '+00:00'))
                except:
                    location_time = current_time
            
            time_diff = (current_time - location_time).total_seconds()
            is_online = time_diff < 120
            
            loc_data = {
                'device_id': location['device_id'],
                'device_name': location.get('device_name', 'Unknown'),
                'os': location.get('os', 'Unknown'),
                'latitude': location.get('latitude', 0),
                'longitude': location.get('longitude', 0),
                'accuracy': location.get('accuracy', 0),
                'timestamp': location_time.isoformat(),
                'is_online': is_online,
                'current_section': location.get('current_section', 'Outside Campus'),
                'validation_reason': 'live_tracking'
            }
            
            all_locations.append(loc_data)
        
        return jsonify({
            'locations': all_locations
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system-status', methods=['GET'])
@token_required
def system_status(current_user):
    try:
        user_count = users_collection.count_documents({})
        device_count = devices_collection.count_documents({})
        location_count = locations_collection.count_documents({})
        connected_devices_count = device_connections_collection.count_documents({'is_online': True})
        
        return jsonify({
            'status': 'online',
            'users': user_count,
            'devices': device_count,
            'active_locations': location_count,
            'connected_devices': connected_devices_count,
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'multi_device_active': True
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/locations', methods=['GET'])
@token_required
def debug_locations(current_user):
    try:
        all_locations = list(locations_collection.find(
            {'user_email': current_user['email']},
            {'_id': 0}
        ).sort('timestamp', -1).limit(50))
        
        device_ids = list(set([loc['device_id'] for loc in all_locations]))
        devices = {d['device_id']: d for d in devices_collection.find(
            {'device_id': {'$in': device_ids}},
            {'device_name': 1, 'os': 1, '_id': 0}
        )}
        
        formatted = []
        for loc in all_locations:
            formatted.append({
                'device_id': loc['device_id'],
                'device_name': devices.get(loc['device_id'], {}).get('device_name', 'Unknown'),
                'latitude': loc.get('latitude', 0),
                'longitude': loc.get('longitude', 0),
                'accuracy': loc.get('accuracy', 0),
                'timestamp': loc.get('timestamp', datetime.datetime.utcnow()).isoformat() if not isinstance(loc.get('timestamp'), str) else loc.get('timestamp'),
                'validation_reason': loc.get('validation_reason', 'unknown'),
                'current_section': loc.get('current_section', 'Unknown')
            })
        
        return jsonify({
            'total_locations': len(formatted),
            'locations': formatted,
            'device_count': len(devices)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)