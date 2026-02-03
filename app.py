from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit, join_room, disconnect
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
import uuid
import urllib.parse
import traceback

from behavior_analyzer import BehaviorAnalyzer
from ml_model import DeviceBehaviorModel

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
    devices_collection.create_index([('user_email', 1), ('ua_fingerprint', 1)], background=True)

    users_collection.create_index([('email', 1)], unique=True, background=True)
    locations_collection.create_index([('device_id', 1)], background=True)
    locations_collection.create_index([('timestamp', -1)], background=True)
    locations_collection.create_index([('user_email', 1)], background=True)
    locations_collection.create_index([('device_id', 1), ('timestamp', -1)], background=True)
    university_collection.create_index([('user_email', 1)], unique=True, background=True)

    device_connections_collection.create_index([('device_id', 1)], unique=True, background=True)
    device_connections_collection.create_index([('user_email', 1)], background=True)
    device_connections_collection.create_index([('socket_id', 1)], background=True)
    device_locations_collection.create_index([('device_id', 1)], unique=True, background=True)
    device_locations_collection.create_index([('user_email', 1)], background=True)
    device_locations_collection.create_index([('timestamp', -1)], background=True)
except Exception as e:
    print(f"Index creation warning: {e}")

JWT_SECRET = os.getenv("JWT_SECRET", "default_secret_key")

behavior_analyzer = BehaviorAnalyzer(db)
user_models = {}
training_threads = {}
model_lock = threading.Lock()

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

def build_server_fingerprint(user_agent):
    if not user_agent:
        return ''
    return hashlib.sha256(user_agent.encode('utf-8')).hexdigest()

def find_existing_device_for_user(user_email, device_id, user_agent):
    device = devices_collection.find_one({
        'device_id': device_id,
        'user_email': user_email
    })
    if device:
        print(f"find_existing: exact device_id match for {user_email}")
        return device

    if user_agent:
        ua_hash = build_server_fingerprint(user_agent)
        device = devices_collection.find_one({
            'user_email': user_email,
            'ua_fingerprint': ua_hash
        })
        if device:
            print(f"find_existing: UA-fingerprint match for {user_email} - recovering device_id {device['device_id'][:16]}...")
            return device

    return None

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
    if device_id in ('null', 'undefined', 'None'):
        return False
    if len(device_id) < 5:
        return False
    return True

def generate_university_layout(center_lat, center_lon):
    sections = []
    section_size = UNIVERSITY_SIZE / 3
    start_lat = center_lat + UNIVERSITY_SIZE / 2
    start_lon = center_lon - UNIVERSITY_SIZE / 2

    for sc in SECTION_CONFIGS:
        row, col = sc['row'], sc['col']
        min_lat = start_lat - (row + 1) * section_size
        max_lat = start_lat - row * section_size
        min_lon = start_lon + col * section_size
        max_lon = start_lon + (col + 1) * section_size
        sections.append({
            'name': sc['name'],
            'color': sc['color'],
            'bounds': {'min_lat': min_lat, 'max_lat': max_lat, 'min_lon': min_lon, 'max_lon': max_lon},
            'center': {'lat': (min_lat + max_lat) / 2, 'lon': (min_lon + max_lon) / 2},
            'size_meters': 12.0
        })
    print(f"Generated university with {len(sections)} sections (12x12m each)")
    return sections

def detect_section(latitude, longitude, sections):
    for section in sections:
        b = section['bounds']
        if b['min_lat'] <= latitude <= b['max_lat'] and b['min_lon'] <= longitude <= b['max_lon']:
            return section['name']
    return 'Outside Campus'

def detect_os(user_agent):
    if not user_agent:
        return 'Unknown'
    ua = user_agent.lower()
    if 'iphone' in ua or 'ipad' in ua or 'ipod' in ua:
        return 'iPhone'
    elif 'android' in ua:
        return 'Android'
    elif 'mac' in ua or 'macintosh' in ua:
        return 'Mac'
    elif 'windows' in ua:
        return 'Windows'
    system = platform.system()
    if system == 'Darwin':
        return 'Mac'
    if system == 'Windows':
        return 'Windows'
    return 'Unknown'

def detect_browser(user_agent):
    if not user_agent:
        return 'Unknown'
    ua = user_agent.lower()
    if 'chrome' in ua and 'edg' not in ua:
        return 'Chrome'
    if 'safari' in ua and 'chrome' not in ua:
        return 'Safari'
    if 'firefox' in ua:
        return 'Firefox'
    if 'edge' in ua or 'edg' in ua:
        return 'Edge'
    if 'opera' in ua or 'opr' in ua:
        return 'Opera'
    return 'Unknown'

def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

def constrain_location_to_radius(new_lat, new_lon, anchor_lat, anchor_lon, max_radius):
    distance = calculate_distance(anchor_lat, anchor_lon, new_lat, new_lon)
    if distance <= max_radius:
        return new_lat, new_lon, distance
    phi1 = math.radians(anchor_lat)
    phi2 = math.radians(new_lat)
    lam1 = math.radians(anchor_lon)
    lam2 = math.radians(new_lon)
    y = math.sin(lam2 - lam1) * math.cos(phi2)
    x = math.cos(phi1)*math.sin(phi2) - math.sin(phi1)*math.cos(phi2)*math.cos(lam2 - lam1)
    bearing = math.atan2(y, x)
    R = 6371000
    ad = max_radius / R
    clat = math.asin(math.sin(phi1)*math.cos(ad) + math.cos(phi1)*math.sin(ad)*math.cos(bearing))
    clon = lam1 + math.atan2(math.sin(bearing)*math.sin(ad)*math.cos(phi1), math.cos(ad) - math.sin(phi1)*math.sin(clat))
    return math.degrees(clat), math.degrees(clon), distance

def validate_and_constrain_location(device_id, latitude, longitude, accuracy):
    if not validate_device_id(device_id):
        return None, None, None, False, "invalid_device_id"

    last_location = locations_collection.find_one({'device_id': device_id}, sort=[('timestamp', -1)])

    if accuracy < HIGH_ACCURACY_THRESHOLD:
        print(f"HIGH ACCURACY: {device_id[:8]}... {accuracy:.1f}m - ACCEPTED")
        return latitude, longitude, accuracy, True, "high_accuracy_accepted"

    if last_location and 'latitude' in last_location and 'longitude' in last_location:
        anchor_lat, anchor_lon = last_location['latitude'], last_location['longitude']
        distance = calculate_distance(anchor_lat, anchor_lon, latitude, longitude)
        if distance > MAX_POSITION_DRIFT:
            clat, clon, _ = constrain_location_to_radius(latitude, longitude, anchor_lat, anchor_lon, MAX_POSITION_DRIFT)
            print(f"CONSTRAINED: {device_id[:8]}...")
            return clat, clon, accuracy, True, "constrained_to_radius"
        else:
            print(f"ACCEPTED: {device_id[:8]}... moved {distance:.1f}m")
            return latitude, longitude, accuracy, True, "within_drift_limit"
    else:
        print(f"FIRST LOCATION: {device_id[:8]}... accuracy {accuracy:.1f}m")
        return latitude, longitude, accuracy, True, "first_location_accepted"

def start_ml_training(user_email):
    print(f"Starting ML training for {user_email}")
    with model_lock:
        if user_email not in user_models:
            user_models[user_email] = DeviceBehaviorModel(user_email)
        model = user_models[user_email]
        model.training_start_time = datetime.datetime.utcnow()

    behavior_analyzer.update_training_status(user_email, {
        'training_started': datetime.datetime.utcnow(),
        'is_training': True,
        'is_trained': False,
        'training_samples': 0,
        'last_update': datetime.datetime.utcnow()
    })
    try:
        socketio.emit('ml_status_update', {
            'is_training': True, 'is_trained': False, 'training_samples': 0,
            'message': 'ML training started. Collecting behavior data...'
        }, room=user_email)
    except Exception as e:
        print(f"Could not emit ML status: {e}")
    return True

def check_and_train_model(user_email):
    with model_lock:
        if user_email not in user_models:
            user_models[user_email] = DeviceBehaviorModel(user_email)
        model = user_models[user_email]

    training_status = behavior_analyzer.get_training_status(user_email)

    if training_status and training_status.get('is_trained'):
        model_path = f"models/{user_email}_model.pkl"
        if model.load_model(model_path):
            print(f"Loaded trained model for {user_email}")
            return True
        else:
            behavior_analyzer.update_training_status(user_email, {
                'is_training': True, 'is_trained': False, 'training_samples': 0
            })

    user = users_collection.find_one({'email': user_email})
    device_count = len(user.get('devices', [])) if user else 0
    if device_count < 2:
        return False

    if not training_status:
        start_ml_training(user_email)
        return False

    if training_status.get('is_training'):
        training_started = training_status.get('training_started')
        current_time = datetime.datetime.utcnow()
        elapsed_minutes = (current_time - training_started).total_seconds() / 60

        behavior_data = behavior_analyzer.get_training_data(user_email, limit=200)
        sample_count = len(behavior_data)

        behavior_analyzer.update_training_status(user_email, {
            'training_samples': sample_count, 'last_update': current_time
        })

        try:
            socketio.emit('ml_training_progress', {
                'samples': sample_count, 'elapsed_minutes': elapsed_minutes,
                'target_minutes': 5, 'message': f'Collecting: {sample_count}/30 samples'
            }, room=user_email)
        except Exception as e:
            print(f"Could not emit training progress: {e}")

        if sample_count >= 30 or elapsed_minutes >= 5:
            print(f"Training ML model for {user_email} with {sample_count} samples...")
            device_patterns = {}
            for did in user.get('devices', []):
                p = behavior_analyzer.get_device_pattern(user_email, did)
                if p:
                    device_patterns[did] = p

            success, message = model.train_model(behavior_data, device_patterns)
            if success:
                model_path = f"models/{user_email}_model.pkl"
                os.makedirs("models", exist_ok=True)
                model.save_model(model_path)
                behavior_analyzer.update_training_status(user_email, {
                    'is_training': False, 'is_trained': True,
                    'training_completed': datetime.datetime.utcnow(),
                    'training_samples': sample_count,
                    'model_path': model_path,
                    'model_info': model.get_model_info()
                })
                print(f"ML Model trained successfully for {user_email}")
                try:
                    socketio.emit('ml_training_complete', {
                        'message': 'Security system activated!',
                        'samples': sample_count,
                        'model_info': model.get_model_info()
                    }, room=user_email)
                except Exception as e:
                    print(f"Could not emit training complete: {e}")
                return True
            else:
                print(f"ML Training failed: {message}")
                return False
    return False

def analyze_device_behavior(user_email, device_locs):
    if len(device_locs) < 2:
        return None

    valid = {did: loc for did, loc in device_locs.items() if validate_device_id(did)}
    if len(valid) < 2:
        return None

    university_data = university_collection.find_one({'user_email': user_email})
    if not university_data or 'sections' not in university_data:
        return None

    sections = university_data['sections']
    device_list = list(valid.values())

    meaningful_movement = False
    for device in device_list:
        last_loc = locations_collection.find_one(
            {'device_id': device['device_id']}, sort=[('timestamp', -1), ('_id', -1)])
        if last_loc and 'latitude' in last_loc:
            if calculate_distance(last_loc['latitude'], last_loc['longitude'],
                                  device['latitude'], device['longitude']) > 3.0:
                meaningful_movement = True
                break
    if not meaningful_movement:
        return None

    for i in range(len(device_list)):
        for j in range(i + 1, len(device_list)):
            d1, d2 = device_list[i], device_list[j]
            if not validate_device_id(d1['device_id']) or not validate_device_id(d2['device_id']):
                continue

            d1['current_section'] = detect_section(d1['latitude'], d1['longitude'], sections)
            d2['current_section'] = detect_section(d2['latitude'], d2['longitude'], sections)

            behavior_record = behavior_analyzer.analyze_device_pair(user_email, d1, d2)
            model_ready = check_and_train_model(user_email)

            if model_ready:
                with model_lock:
                    if user_email in user_models:
                        model = user_models[user_email]
                        is_anomaly, confidence, message, anomaly_details = model.predict_anomaly(behavior_record)
                        if is_anomaly:
                            print(f"ANOMALY for {user_email}! Score={anomaly_details['score']:.3f}")
                            d1_anom, d1_det = model.detect_individual_anomaly(
                                {'section_id': behavior_analyzer.get_section_id(d1['current_section']),
                                 'speed': behavior_record.get('movement_speed_device1', 0)},
                                {'section_id': behavior_analyzer.get_section_id(d2['current_section']),
                                 'distance_to_other': behavior_record['distance_between_devices'],
                                 'with_other_device': d2['device_id']})
                            d2_anom, d2_det = model.detect_individual_anomaly(
                                {'section_id': behavior_analyzer.get_section_id(d2['current_section']),
                                 'speed': behavior_record.get('movement_speed_device2', 0)},
                                {'section_id': behavior_analyzer.get_section_id(d1['current_section']),
                                 'distance_to_other': behavior_record['distance_between_devices'],
                                 'with_other_device': d1['device_id']})

                            alert_data = {
                                'message': 'Unusual device behavior detected!',
                                'device1': d1['device_id'], 'device2': d2['device_id'],
                                'device1_section': d1['current_section'],
                                'device2_section': d2['current_section'],
                                'distance': behavior_record['distance_between_devices'],
                                'confidence': confidence,
                                'score': anomaly_details['score'],
                                'threshold': anomaly_details['threshold'],
                                'cluster_distance': anomaly_details.get('cluster_distance', 0),
                                'timestamp': datetime.datetime.utcnow().isoformat(),
                                'details': {
                                    'pair_anomaly': True,
                                    'device1_anomaly': d1_anom, 'device2_anomaly': d2_anom,
                                    'device1_reasons': d1_det.get('reasons', []) if d1_anom else [],
                                    'device2_reasons': d2_det.get('reasons', []) if d2_anom else [],
                                    'feature_analysis': anomaly_details.get('features', {})
                                }
                            }
                            try:
                                socketio.emit('anomaly_alert', alert_data, room=user_email)
                            except Exception as e:
                                print(f"Could not emit anomaly alert: {e}")

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
        print(f"New WebSocket connection: {request.sid}")
        device_id = extract_device_id_from_request()

        if device_id and validate_device_id(device_id):
            device_connections_collection.update_one(
                {'device_id': device_id},
                {'$set': {
                    'socket_id': request.sid, 'device_id': device_id,
                    'connected_at': datetime.datetime.utcnow(),
                    'is_online': True, 'last_ping': datetime.datetime.utcnow()
                }},
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
        traceback.print_exc()
        emit('connection_error', {'message': str(e)})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')
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
        print(f"Error cleaning up: {e}")

@socketio.on_error()
def handle_error(e):
    print(f'Socket.IO error: {e}')
    traceback.print_exc()

@socketio.on('join_room')
def handle_join_room(data):
    try:
        print(f"JOIN_ROOM from {request.sid}: {data}")
        user_email = data.get('user_email')
        device_id = data.get('device_id')
        token = data.get('token')

        if not device_id or device_id == 'null':
            conn = device_connections_collection.find_one({'socket_id': request.sid})
            if conn:
                device_id = conn.get('device_id')

        if not device_id or not validate_device_id(device_id):
            emit('join_error', {'message': 'Device ID required.', 'code': 'DEVICE_ID_MISSING'})
            return

        if not user_email:
            emit('join_error', {'message': 'User email required'})
            return

        if token:
            try:
                t = token.split(' ')[1] if token.startswith('Bearer ') else token
                jwt.decode(t, JWT_SECRET, algorithms=["HS256"])
            except Exception as e:
                emit('join_error', {'message': 'Invalid token'})
                return

        device_exists = devices_collection.find_one({'device_id': device_id})
        if not device_exists:
            emit('join_error', {
                'message': 'Device not registered. Please add device first.',
                'code': 'DEVICE_NOT_REGISTERED', 'device_id': device_id
            })
            return
        if device_exists['user_email'] != user_email:
            emit('join_error', {'message': 'Device registered to another account', 'code': 'DEVICE_WRONG_USER'})
            return

        device_connections_collection.update_one(
            {'device_id': device_id},
            {'$set': {
                'socket_id': request.sid, 'user_email': user_email, 'device_id': device_id,
                'connected_at': datetime.datetime.utcnow(), 'is_online': True,
                'last_ping': datetime.datetime.utcnow()
            }},
            upsert=True
        )
        connected_devices[device_id] = request.sid
        if user_email not in user_devices:
            user_devices[user_email] = set()
        user_devices[user_email].add(device_id)

        join_room(user_email)
        print(f'Device {device_id[:16]} joined room for {user_email}')

        device_name = device_exists.get('device_name', 'Unknown Device')
        device_os = device_exists.get('os', 'Unknown')

        device_locations_collection.update_one(
            {'device_id': device_id},
            {'$set': {
                'device_id': device_id, 'device_name': device_name, 'os': device_os,
                'user_email': user_email, 'is_online': True, 'socket_id': request.sid,
                'last_seen': datetime.datetime.utcnow(), 'connected_at': datetime.datetime.utcnow()
            }},
            upsert=True
        )

        emit('join_confirmation', {
            'message': f'Joined room for {user_email}',
            'user_email': user_email, 'device_id': device_id,
            'device_name': device_name, 'device_os': device_os
        })

        try:
            user = users_collection.find_one({'email': user_email})
            if user and 'devices' in user:
                for did in user['devices']:
                    if not validate_device_id(did):
                        continue
                    location = device_locations_collection.find_one({'device_id': did}, {'_id': 0})
                    if not location:
                        location = locations_collection.find_one({'device_id': did}, sort=[('timestamp', -1)])
                    if location:
                        dinfo = devices_collection.find_one({'device_id': did})
                        socketio.emit('location_update', {
                            'device_id': did,
                            'device_name': dinfo.get('device_name', 'Unknown') if dinfo else 'Unknown',
                            'os': dinfo.get('os', 'Unknown') if dinfo else 'Unknown',
                            'latitude': location.get('latitude', 0),
                            'longitude': location.get('longitude', 0),
                            'accuracy': location.get('accuracy', 0),
                            'timestamp': location.get('timestamp', datetime.datetime.utcnow()).isoformat() if not isinstance(location.get('timestamp'), str) else location.get('timestamp'),
                            'validation_reason': location.get('validation_reason', 'initial'),
                            'current_section': location.get('current_section', 'Outside Campus'),
                            'is_online': did in connected_devices
                        }, room=user_email)
        except Exception as e:
            print(f"Error sending initial locations: {e}")

        training_status = behavior_analyzer.get_training_status(user_email)
        if training_status:
            try:
                emit('ml_status_update', {
                    'is_training': training_status.get('is_training', False),
                    'is_trained': training_status.get('is_trained', False),
                    'training_samples': training_status.get('training_samples', 0),
                    'message': training_status.get('message', '')
                })
            except Exception as e:
                print(f"Could not emit ML status: {e}")

        try:
            socketio.emit('device_connected', {
                'device_id': device_id, 'device_name': device_name,
                'os': device_os, 'timestamp': datetime.datetime.utcnow().isoformat()
            }, room=user_email)
        except Exception as e:
            print(f"Could not emit device connected: {e}")

    except Exception as e:
        print(f"Error in join_room: {e}")
        traceback.print_exc()
        emit('join_error', {'message': str(e)})

@socketio.on('update_location')
def handle_location_update(data):
    try:
        print(f"UPDATE_LOCATION from {request.sid}")
        device_id = data.get('device_id')
        user_email = data.get('user_email')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        accuracy = data.get('accuracy', 0)

        if not device_id or device_id == 'null':
            conn = device_connections_collection.find_one({'socket_id': request.sid})
            if conn:
                device_id = conn.get('device_id')
                user_email = conn.get('user_email', user_email)

        if not all([device_id, user_email, latitude, longitude]):
            emit('location_error', {'message': 'Missing required fields'})
            return
        if not validate_device_id(device_id):
            emit('location_error', {'message': 'Invalid Device ID'})
            return

        raw_lat, raw_lng, acc = float(latitude), float(longitude), float(accuracy)

        validated_lat, validated_lng, validated_acc, is_valid, reason = \
            validate_and_constrain_location(device_id, raw_lat, raw_lng, acc)

        if not is_valid:
            try:
                socketio.emit('location_rejected', {
                    'device_id': device_id, 'reason': reason, 'original_accuracy': acc
                }, room=user_email)
            except Exception as e:
                print(f"Could not emit location rejected: {e}")
            return

        current_time = datetime.datetime.utcnow()

        device_info = devices_collection.find_one({'device_id': device_id})
        device_name = device_info.get('device_name', 'Unknown') if device_info else 'Unknown'
        device_os = device_info.get('os', 'Unknown') if device_info else 'Unknown'

        university_data = university_collection.find_one({'user_email': user_email})
        current_section = 'Outside Campus'
        if university_data and 'sections' in university_data:
            current_section = detect_section(validated_lat, validated_lng, university_data['sections'])

        locations_collection.insert_one({
            'device_id': device_id, 'latitude': validated_lat, 'longitude': validated_lng,
            'accuracy': validated_acc, 'timestamp': current_time, 'user_email': user_email,
            'validation_reason': reason, 'current_section': current_section,
            'raw_latitude': raw_lat, 'raw_longitude': raw_lng, 'raw_accuracy': acc
        })

        device_locations_collection.update_one(
            {'device_id': device_id},
            {'$set': {
                'device_id': device_id, 'device_name': device_name, 'os': device_os,
                'latitude': validated_lat, 'longitude': validated_lng, 'accuracy': validated_acc,
                'user_email': user_email, 'current_section': current_section,
                'timestamp': current_time, 'is_online': True, 'last_seen': current_time
            }},
            upsert=True
        )

        devices_collection.update_one(
            {'device_id': device_id},
            {'$set': {
                'last_seen': current_time, 'location_tracking': True,
                'last_latitude': validated_lat, 'last_longitude': validated_lng,
                'last_accuracy': validated_acc, 'current_section': current_section
            }}
        )

        broadcast_data = {
            'device_id': device_id, 'device_name': device_name, 'os': device_os,
            'latitude': validated_lat, 'longitude': validated_lng, 'accuracy': validated_acc,
            'timestamp': current_time.isoformat(), 'validation_reason': reason,
            'current_section': current_section, 'is_online': True
        }
        try:
            socketio.emit('location_update', broadcast_data, room=user_email)
        except Exception as e:
            print(f"Could not emit location update: {e}")

        user = users_collection.find_one({'email': user_email})
        if user and len(user.get('devices', [])) >= 2:
            try:
                udl = {}
                for did in user.get('devices', []):
                    if not validate_device_id(did):
                        continue
                    loc = device_locations_collection.find_one({'device_id': did})
                    if loc:
                        udl[did] = loc
                if len(udl) >= 2:
                    thread = threading.Thread(target=analyze_device_behavior, args=(user_email, udl))
                    thread.daemon = True
                    thread.start()
            except Exception as e:
                print(f"ML analysis setup failed: {e}")

    except Exception as e:
        print(f"Error in update_location: {e}")
        traceback.print_exc()

@app.route('/')
def home():
    return jsonify({'message': 'Tracker API is running', 'status': 'online',
                    'timestamp': datetime.datetime.utcnow().isoformat()})

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        client.admin.command('ping')
        models_dir = 'models'
        model_count = len([f for f in os.listdir(models_dir) if f.endswith('.pkl')]) if os.path.exists(models_dir) else 0
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'database': 'connected',
            'ml_models': model_count,
            'active_users': len(user_models),
            'connected_devices': len(connected_devices),
            'websocket_support': True,
            'multi_device_support': True,
            'duplicate_device_fix': 'APPLIED_V4_FINGERPRINT'
        }), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        email, password = data.get('email'), data.get('password')
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        if users_collection.find_one({'email': email}):
            return jsonify({'error': 'User already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = {
            'email': email, 'password': hashed_password,
            'created_at': datetime.datetime.utcnow(),
            'devices': [], 'location_permission': False,
            'last_login': datetime.datetime.utcnow()
        }
        result = users_collection.insert_one(user)
        user['_id'] = str(result.inserted_id)

        token = jwt.encode({'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)}, JWT_SECRET)
        user.pop('password', None)
        print(f"User registered: {email}")
        return jsonify({'message': 'User registered successfully', 'token': token, 'user': serialize_document(user)}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        email, password = data.get('email'), data.get('password')
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        user = users_collection.find_one({'email': email})
        if not user or not bcrypt.check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401

        token = jwt.encode({'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)}, JWT_SECRET)
        users_collection.update_one({'email': email}, {'$set': {'last_login': datetime.datetime.utcnow()}})

        user_data = serialize_document(user)
        user_data.pop('password', None)
        print(f"User logged in: {email}")
        return jsonify({'message': 'Login successful', 'token': token, 'user': user_data}), 200
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
            device_id = hashlib.sha256((system_info + user_agent).encode()).hexdigest()

        os_name = detect_os(user_agent)

        existing_device = find_existing_device_for_user(
            current_user['email'], device_id, user_agent
        )

        if existing_device:
            print(f"check-device: found existing device {existing_device['device_id'][:16]} for {current_user['email']}")
            return jsonify({
                'device_id': existing_device['device_id'],
                'device_exists': True,
                'user_has_device': True,
                'device_status': 'registered_to_me',
                'device_owner': current_user['email'],
                'os': existing_device.get('os', os_name),
                'location_permission': current_user.get('location_permission', False)
            }), 200

        other_device = devices_collection.find_one({'device_id': device_id})
        if other_device and other_device['user_email'] != current_user['email']:
            return jsonify({
                'device_id': device_id,
                'device_exists': True,
                'user_has_device': False,
                'device_status': 'registered_to_other',
                'device_owner': other_device['user_email'],
                'os': os_name,
                'location_permission': current_user.get('location_permission', False)
            }), 200

        print(f"check-device: device {device_id[:16]} not registered for {current_user['email']}")
        return jsonify({
            'device_id': device_id,
            'device_exists': False,
            'user_has_device': False,
            'device_status': 'not_registered',
            'device_owner': None,
            'os': os_name,
            'location_permission': current_user.get('location_permission', False)
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/add-device', methods=['POST'])
@token_required
def add_device(current_user):
    try:
        data = request.json
        device_id = data.get('device_id')
        device_name = data.get('device_name', 'My Device')
        user_agent = request.headers.get('User-Agent', '')

        if not device_id or not validate_device_id(device_id):
            return jsonify({'error': 'Valid Device ID is required'}), 400

        existing_device = devices_collection.find_one({'device_id': device_id})
        if existing_device:
            if existing_device['user_email'] == current_user['email']:
                print(f"add-device: device {device_id[:16]} already belongs to {current_user['email']} - returning OK")
                return jsonify({
                    'message': 'Device already registered to your account',
                    'device': serialize_document(existing_device),
                    'device_status': {
                        'device_id': device_id,
                        'device_exists': True,
                        'user_has_device': True,
                        'device_status': 'registered_to_me',
                        'device_owner': current_user['email'],
                        'os': existing_device.get('os', 'Unknown')
                    },
                    'ml_training_started': False,
                    'device_count': len(current_user.get('devices', []))
                }), 201
            else:
                return jsonify({'error': 'Device already registered to another account'}), 400

        ua_hash = build_server_fingerprint(user_agent)
        existing_by_ua = devices_collection.find_one({
            'user_email': current_user['email'],
            'ua_fingerprint': ua_hash
        })
        if existing_by_ua:
            old_id = existing_by_ua['device_id']
            print(f"add-device: UA match found. Updating device_id {old_id[:16]} -> {device_id[:16]}")

            devices_collection.update_one(
                {'_id': existing_by_ua['_id']},
                {'$set': {
                    'device_id': device_id,
                    'device_name': device_name,
                    'last_seen': datetime.datetime.utcnow()
                }}
            )
            users_collection.update_one(
                {'email': current_user['email']},
                {'$pull': {'devices': old_id}}
            )
            users_collection.update_one(
                {'email': current_user['email']},
                {'$addToSet': {'devices': device_id}}
            )
            locations_collection.update_many(
                {'device_id': old_id},
                {'$set': {'device_id': device_id}}
            )
            device_locations_collection.update_one(
                {'device_id': old_id},
                {'$set': {'device_id': device_id}}
            )

            updated_device = devices_collection.find_one({'device_id': device_id})
            updated_user = users_collection.find_one({'email': current_user['email']})

            return jsonify({
                'message': 'Device updated (recovered from previous session)',
                'device': serialize_document(updated_device),
                'device_status': {
                    'device_id': device_id,
                    'device_exists': True,
                    'user_has_device': True,
                    'device_status': 'registered_to_me',
                    'device_owner': current_user['email'],
                    'os': updated_device.get('os', 'Unknown')
                },
                'ml_training_started': len(updated_user.get('devices', [])) >= 2,
                'device_count': len(updated_user.get('devices', []))
            }), 201

        os_name = detect_os(user_agent)
        browser = detect_browser(user_agent)

        device = {
            'device_id': device_id,
            'device_name': device_name,
            'user_email': current_user['email'],
            'added_at': datetime.datetime.utcnow(),
            'os': os_name,
            'browser': browser,
            'user_agent': user_agent,
            'ua_fingerprint': ua_hash,
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

        print(f"New device added: {device_id[:16]} for {current_user['email']}")

        updated_user = users_collection.find_one({'email': current_user['email']})
        device_count = len(updated_user.get('devices', []))

        return jsonify({
            'message': 'Device added successfully',
            'device': serialize_document(device),
            'device_status': {
                'device_id': device_id,
                'device_exists': True,
                'user_has_device': True,
                'device_status': 'registered_to_me',
                'device_owner': current_user['email'],
                'os': os_name
            },
            'ml_training_started': device_count >= 2,
            'device_count': device_count
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user-devices', methods=['GET'])
@token_required
def get_user_devices(current_user):
    try:
        user = users_collection.find_one({'email': current_user['email']}, {'devices': 1, '_id': 0})
        if not user or not user.get('devices'):
            return jsonify({'devices': []}), 200

        devices_cursor = devices_collection.find(
            {'device_id': {'$in': user['devices']}},
            {'device_id': 1, 'device_name': 1, 'os': 1, 'location_tracking': 1, 'last_seen': 1, 'current_section': 1, '_id': 0}
        )
        devices = list(devices_cursor)
        for device in devices:
            dloc = device_locations_collection.find_one({'device_id': device['device_id']})
            device['is_online'] = dloc.get('is_online', False) if dloc else False

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

        device = devices_collection.find_one({'device_id': device_id, 'user_email': current_user['email']})
        if not device:
            return jsonify({'error': 'Device not found or not authorized'}), 404

        university_exists = university_collection.find_one({'user_email': current_user['email']})
        if not university_exists and initial_latitude and initial_longitude:
            try:
                center_lat, center_lon = float(initial_latitude), float(initial_longitude)
                sections = generate_university_layout(center_lat, center_lon)
                university_collection.insert_one({
                    'user_email': current_user['email'],
                    'center': {'lat': center_lat, 'lon': center_lon},
                    'sections': sections,
                    'created_at': datetime.datetime.utcnow(),
                    'total_size_meters': UNIVERSITY_SIZE * 111000
                })
                print(f"University created at {center_lat}, {center_lon}")
            except ValueError:
                return jsonify({'error': 'Invalid coordinates'}), 400

        users_collection.update_one({'email': current_user['email']}, {'$set': {'location_permission': True}})
        devices_collection.update_one({'device_id': device_id}, {'$set': {'location_tracking': True}})

        university_data = university_collection.find_one({'user_email': current_user['email']})
        return jsonify({
            'message': 'Location permission granted successfully',
            'location_permission': True, 'device_id': device_id,
            'university': serialize_document(university_data) if university_data else None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/university-layout', methods=['GET'])
@token_required
def get_university_layout(current_user):
    try:
        university_data = university_collection.find_one({'user_email': current_user['email']})
        return jsonify({'university': serialize_document(university_data) if university_data else None}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/all-devices-locations', methods=['GET'])
@token_required
def get_all_devices_locations(current_user):
    try:
        cursor = device_locations_collection.find(
            {'user_email': current_user['email']}, {'_id': 0}
        ).sort('timestamp', -1)

        all_locations = []
        current_time = datetime.datetime.utcnow()
        for location in cursor:
            loc_time = location.get('timestamp', current_time)
            if isinstance(loc_time, str):
                try:
                    loc_time = datetime.datetime.fromisoformat(loc_time.replace('Z', '+00:00'))
                except:
                    loc_time = current_time
            is_online = (current_time - loc_time).total_seconds() < 120

            all_locations.append({
                'device_id': location['device_id'],
                'device_name': location.get('device_name', 'Unknown'),
                'os': location.get('os', 'Unknown'),
                'latitude': location.get('latitude', 0),
                'longitude': location.get('longitude', 0),
                'accuracy': location.get('accuracy', 0),
                'timestamp': loc_time.isoformat(),
                'is_online': is_online,
                'current_section': location.get('current_section', 'Outside Campus'),
                'validation_reason': 'live_tracking'
            })

        return jsonify({'locations': all_locations}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ml-status', methods=['GET'])
@token_required
def get_ml_status(current_user):
    try:
        training_status = behavior_analyzer.get_training_status(current_user['email'])
        if not training_status:
            user = users_collection.find_one({'email': current_user['email']})
            dc = len(user.get('devices', [])) if user else 0
            status = {
                'is_training': False, 'is_trained': False, 'training_samples': 0,
                'device_count': dc, 'can_start_training': dc >= 2
            }
            status['message'] = 'Ready to start ML training.' if dc >= 2 else f'Add {2-dc} more device(s)'
            return jsonify(status), 200

        model_info = {}
        if training_status.get('is_trained') and current_user['email'] in user_models:
            with model_lock:
                model_info = user_models[current_user['email']].get_model_info()

        response = {
            'is_training': training_status.get('is_training', False),
            'is_trained': training_status.get('is_trained', False),
            'training_samples': training_status.get('training_samples', 0),
            'training_started': training_status.get('training_started', '').isoformat() if training_status.get('training_started') else None,
            'training_completed': training_status.get('training_completed', '').isoformat() if training_status.get('training_completed') else None,
            'model_info': model_info,
            'message': training_status.get('message', '')
        }
        if training_status.get('is_training') and training_status.get('training_started'):
            elapsed = (datetime.datetime.utcnow() - training_status['training_started']).total_seconds() / 60
            response['elapsed_minutes'] = round(elapsed, 1)
            response['remaining_minutes'] = round(max(0, 5 - elapsed), 1)
            response['progress_percentage'] = min(100, int((elapsed / 5) * 100))

        return jsonify(response), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/start-ml-training', methods=['POST'])
@token_required
def start_ml_training_route(current_user):
    try:
        user = users_collection.find_one({'email': current_user['email']})
        dc = len(user.get('devices', [])) if user else 0
        if dc < 2:
            return jsonify({'success': False, 'message': f'Need 2+ devices. Have {dc}.'}), 400

        ts = behavior_analyzer.get_training_status(current_user['email'])
        if ts and (ts.get('is_training') or ts.get('is_trained')):
            return jsonify({'success': False, 'message': 'ML training already in progress or completed'}), 400

        if start_ml_training(current_user['email']):
            return jsonify({
                'success': True, 'message': 'ML training started.',
                'estimated_completion': (datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).isoformat()
            }), 200
        return jsonify({'success': False, 'message': 'Failed to start'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/device-patterns', methods=['GET'])
@token_required
def get_device_patterns(current_user):
    try:
        user = users_collection.find_one({'email': current_user['email']})
        if not user:
            return jsonify({'patterns': {}}), 200
        device_patterns = {}
        for did in user.get('devices', []):
            p = behavior_analyzer.get_device_pattern(current_user['email'], did)
            if p:
                p.pop('_id', None)
                if 'section_visits' in p:
                    total = sum(p['section_visits'].values())
                    p['section_percentages'] = {s: (c/total*100) if total else 0 for s, c in p['section_visits'].items()}
                device_patterns[did] = p
        return jsonify({'patterns': device_patterns, 'device_count': len(device_patterns)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system-status', methods=['GET'])
@token_required
def system_status(current_user):
    try:
        models_dir = 'models'
        trained_models = len([f for f in os.listdir(models_dir) if f.endswith('.pkl')]) if os.path.exists(models_dir) else 0
        return jsonify({
            'status': 'online',
            'users': users_collection.count_documents({}),
            'devices': devices_collection.count_documents({}),
            'active_locations': locations_collection.count_documents({}),
            'behavior_records': behavior_analyzer.behavior_collection.count_documents({}),
            'trained_ml_models': trained_models,
            'active_ml_models': len(user_models),
            'connected_devices': device_connections_collection.count_documents({'is_online': True}),
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'duplicate_device_fix': 'APPLIED_V4_FINGERPRINT'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/locations', methods=['GET'])
@token_required
def debug_locations(current_user):
    try:
        all_locations = list(locations_collection.find(
            {'user_email': current_user['email']}, {'_id': 0}
        ).sort('timestamp', -1).limit(50))

        device_ids = list(set([loc['device_id'] for loc in all_locations]))
        devices = {d['device_id']: d for d in devices_collection.find(
            {'device_id': {'$in': device_ids}}, {'device_name': 1, 'os': 1, '_id': 0}
        )}
        formatted = []
        for loc in all_locations:
            formatted.append({
                'device_id': loc['device_id'],
                'device_name': devices.get(loc['device_id'], {}).get('device_name', 'Unknown'),
                'latitude': loc.get('latitude', 0), 'longitude': loc.get('longitude', 0),
                'accuracy': loc.get('accuracy', 0),
                'timestamp': loc.get('timestamp', datetime.datetime.utcnow()).isoformat() if not isinstance(loc.get('timestamp'), str) else loc.get('timestamp'),
                'validation_reason': loc.get('validation_reason', 'unknown'),
                'current_section': loc.get('current_section', 'Unknown')
            })
        return jsonify({'total_locations': len(formatted), 'locations': formatted, 'device_count': len(devices)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/connected-devices', methods=['GET'])
@token_required
def get_connected_devices(current_user):
    try:
        connected = list(device_connections_collection.find(
            {'user_email': current_user['email'], 'is_online': True},
            {'_id': 0, 'device_id': 1, 'connected_at': 1, 'socket_id': 1}
        ))
        for d in connected:
            info = devices_collection.find_one({'device_id': d['device_id']}, {'device_name': 1, 'os': 1, '_id': 0})
            if info:
                d.update(info)
        return jsonify({'connected_devices': connected, 'count': len(connected)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-device-id', methods=['GET'])
@token_required
def test_device_id(current_user):
    device_id = extract_device_id_from_request()
    return jsonify({
        'device_id_from_extract': device_id,
        'device_id_valid': validate_device_id(device_id),
        'request_args': dict(request.args),
        'user_email': current_user['email']
    })

@app.route('/api/simulate-location', methods=['POST'])
@token_required
def simulate_location(current_user):
    try:
        data = request.json
        device_id = data.get('device_id')
        latitude = data.get('latitude', 40.7128)
        longitude = data.get('longitude', -74.0060)
        accuracy = data.get('accuracy', 10)

        if not device_id:
            user = users_collection.find_one({'email': current_user['email']})
            if user and user.get('devices'):
                device_id = user['devices'][0]
            else:
                return jsonify({'error': 'No device found'}), 400

        update_data = {
            'device_id': device_id, 'user_email': current_user['email'],
            'latitude': latitude, 'longitude': longitude, 'accuracy': accuracy
        }

        conn = device_connections_collection.find_one({
            'device_id': device_id, 'user_email': current_user['email'], 'is_online': True
        })
        if conn:
            try:
                socketio.emit('update_location', update_data, room=conn.get('socket_id'))
                return jsonify({'success': True, 'message': 'Sent via WebSocket', 'data': update_data})
            except Exception as e:
                return jsonify({'success': False, 'message': f'WebSocket error: {e}', 'data': update_data})

        device_locations_collection.update_one(
            {'device_id': device_id},
            {'$set': {
                'device_id': device_id, 'device_name': 'Test Device', 'os': 'Test',
                'latitude': latitude, 'longitude': longitude, 'accuracy': accuracy,
                'user_email': current_user['email'], 'current_section': 'Outside Campus',
                'timestamp': datetime.datetime.utcnow(), 'is_online': True
            }},
            upsert=True
        )
        return jsonify({'success': True, 'message': 'Stored in database', 'data': update_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/force-connect', methods=['POST'])
@token_required
def force_connect(current_user):
    device_id = request.json.get('device_id')
    if not device_id:
        return jsonify({'error': 'Device ID required'}), 400
    device_connections_collection.delete_one({'device_id': device_id})
    return jsonify({'success': True, 'message': 'Connection cleaned up. Reconnect from frontend.', 'device_id': device_id})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    os.makedirs("models", exist_ok=True)

    print(f"Starting server on port {port}")
    print(f"Location validation: high_acc<{HIGH_ACCURACY_THRESHOLD}m | max_acc<{MAX_ACCEPTABLE_ACCURACY}m | max_drift={MAX_POSITION_DRIFT}m")
    print(f"University: 12x12 m sections")
    print(f"ML Anomaly Detection: Active")
    print(f"WebSocket: threading mode")
    print(f"DUPLICATE DEVICE FIX v4:")
    print(f"   - check-device: recovers existing device via UA fingerprint")
    print(f"   - add-device: guards against exact-ID AND UA-fingerprint duplicates")
    print(f"   - add-device: migrates stale device_id when UA match found")
    print(f"   - Devices ONLY created via /api/add-device")
    print(f"   - join_room validates device exists before proceeding")

    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)