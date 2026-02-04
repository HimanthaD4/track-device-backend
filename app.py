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

# Configure CORS for WebSocket compatibility
CORS(app, 
     resources={r"/*": {"origins": "*"}},
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-Device-ID"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Enhanced WebSocket configuration for Render.com
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=1e8,
    transports=['websocket', 'polling'],
    logger=True,  # ✅ Enable for debugging
    engineio_logger=True  # ✅ Enable for debugging
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

# ✅ FIX: Add collections for multi-device tracking
device_connections_collection = db.device_connections
device_locations_collection = db.device_locations_live

# Create indexes
try:
    devices_collection.create_index([('device_id', 1)], unique=True, background=True)
    devices_collection.create_index([('user_email', 1)], background=True)
    users_collection.create_index([('email', 1)], unique=True, background=True)
    locations_collection.create_index([('device_id', 1)], background=True)
    locations_collection.create_index([('timestamp', -1)], background=True)
    locations_collection.create_index([('user_email', 1)], background=True)
    locations_collection.create_index([('device_id', 1), ('timestamp', -1)], background=True)
    university_collection.create_index([('user_email', 1)], unique=True, background=True)
    
    # Indexes for multi-device
    device_connections_collection.create_index([('device_id', 1)], unique=True, background=True)
    device_connections_collection.create_index([('user_email', 1)], background=True)
    device_connections_collection.create_index([('socket_id', 1)], background=True)
    device_locations_collection.create_index([('device_id', 1)], unique=True, background=True)
    device_locations_collection.create_index([('user_email', 1)], background=True)
    device_locations_collection.create_index([('timestamp', -1)], background=True)
except Exception as e:
    print(f"Index creation warning: {e}")

JWT_SECRET = os.getenv("JWT_SECRET", "default_secret_key")

# Initialize ML components
behavior_analyzer = BehaviorAnalyzer(db)
user_models = {}
training_threads = {}
model_lock = threading.Lock()

# Multi-device tracking structures
connected_devices = {}  # device_id -> socket_id
user_devices = {}       # user_email -> set(device_id)
device_locations = {}   # device_id -> location_data

# SMART LOCATION VALIDATION SETTINGS
HIGH_ACCURACY_THRESHOLD = 10.0
MAX_ACCEPTABLE_ACCURACY = 100.0
MAX_POSITION_DRIFT = 10.0

# UNIVERSITY CONFIGURATION
UNIVERSITY_SIZE = 0.000324
SECTION_CONFIGS = [
    {'name': 'Main Building', 'color': '#e74c3c', 'row': 0, 'col': 1},
    {'name': 'Library', 'color': '#3498db', 'row': 0, 'col': 2},
    {'name': 'New Building', 'color': '#2ecc71', 'row': 1, 'col': 0},
    {'name': 'Canteen', 'color': '#f39c12', 'row': 1, 'col': 1},
    {'name': 'Sports Complex', 'color': '#9b59b6', 'row': 1, 'col': 2},
    {'name': 'Admin Block', 'color': '#1abc9c', 'row': 2, 'col': 1}
]

# Cache to prevent duplicate location processing
last_location_cache = {}
CACHE_TTL = 2

# ================ ENHANCED DEVICE ID EXTRACTION ================
def extract_device_id_from_request():
    """Extract device_id from WebSocket request - ENHANCED VERSION"""
    try:
        print(f"🔍 Attempting to extract device_id from request...")
        
        # Method 1: Direct from request args (for WebSocket handshake)
        device_id = request.args.get('device_id')
        if device_id:
            print(f"📱 Extracted device_id from request.args: {device_id[:12] if device_id else 'null'}")
            return device_id
        
        # Method 2: From query string in handshake (for Socket.IO)
        try:
            if hasattr(request, 'environ'):
                query_string = request.environ.get('QUERY_STRING', '')
                if query_string:
                    query_params = urllib.parse.parse_qs(query_string)
                    device_id = query_params.get('device_id', [None])[0]
                    if device_id:
                        print(f"📱 Extracted device_id from QUERY_STRING: {device_id[:12] if device_id else 'null'}")
                        return device_id
        except Exception as e:
            print(f"⚠️ Error parsing QUERY_STRING: {e}")
        
        # Method 3: From headers
        device_id = request.headers.get('X-Device-ID')
        if device_id:
            print(f"📱 Extracted device_id from X-Device-ID header: {device_id[:12] if device_id else 'null'}")
            return device_id
        
        # Method 4: From authorization data (for Socket.IO v4+)
        if hasattr(request, 'auth') and request.auth:
            device_id = request.auth.get('device_id')
            if device_id:
                print(f"📱 Extracted device_id from request.auth: {device_id[:12] if device_id else 'null'}")
                return device_id
        
        # Method 5: From socketio.auth in environ
        try:
            if hasattr(request, 'environ'):
                auth_data = request.environ.get('socketio.auth', {})
                if isinstance(auth_data, dict):
                    device_id = auth_data.get('device_id')
                    if device_id:
                        print(f"📱 Extracted device_id from socketio.auth: {device_id[:12] if device_id else 'null'}")
                        return device_id
        except Exception as e:
            print(f"⚠️ Error extracting from socketio.auth: {e}")
        
        print(f"⚠️ Could not extract device_id from any source")
        return None
        
    except Exception as e:
        print(f"❌ Error in extract_device_id_from_request: {e}")
        traceback.print_exc()
        return None

def validate_device_id(device_id):
    """Validate device_id is not null or invalid"""
    if not device_id:
        return False
    if device_id == 'null' or device_id == 'undefined' or device_id == 'None':
        return False
    if len(device_id) < 5:  # Too short to be valid
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
    
    print(f"🏛️ Generated university with {len(sections)} sections (12x12m each)")
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
    """RELAXED VALIDATION FOR DEMO"""
    if not validate_device_id(device_id):
        print(f"❌ INVALID device_id in validation: {device_id}")
        return None, None, None, False, "invalid_device_id"
    
    if accuracy > MAX_ACCEPTABLE_ACCURACY:
        print(f"⚠️ WARNING: Device {device_id[:8]}... accuracy {accuracy:.1f}m")
    
    last_location = locations_collection.find_one(
        {'device_id': device_id}, 
        sort=[('timestamp', -1)]
    )
    
    if accuracy < HIGH_ACCURACY_THRESHOLD:
        print(f"✅ HIGH ACCURACY: Device {device_id[:8]}... {accuracy:.1f}m - ACCEPTED")
        return latitude, longitude, accuracy, True, "high_accuracy_accepted"
    
    if last_location and 'latitude' in last_location and 'longitude' in last_location:
        anchor_lat = last_location['latitude']
        anchor_lon = last_location['longitude']
        distance = calculate_distance(anchor_lat, anchor_lon, latitude, longitude)
        
        if distance > MAX_POSITION_DRIFT:
            constrained_lat, constrained_lon, actual_distance = constrain_location_to_radius(
                latitude, longitude, anchor_lat, anchor_lon, MAX_POSITION_DRIFT
            )
            print(f"🔒 CONSTRAINED: Device {device_id[:8]}... moved {actual_distance:.1f}m")
            return constrained_lat, constrained_lon, accuracy, True, "constrained_to_radius"
        else:
            print(f"✅ ACCEPTED: Device {device_id[:8]}... moved {distance:.1f}m")
            return latitude, longitude, accuracy, True, "within_drift_limit"
    else:
        print(f"✅ FIRST LOCATION: Device {device_id[:8]}... accuracy {accuracy:.1f}m")
        return latitude, longitude, accuracy, True, "first_location_accepted"

def start_ml_training(user_email):
    """Start ML training process for user"""
    print(f"🚀 Starting ML training for {user_email}")
    
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
            'is_training': True,
            'is_trained': False,
            'training_samples': 0,
            'message': 'ML training started. Collecting behavior data...'
        }, room=user_email)
    except Exception as e:
        print(f"⚠️ Could not emit ML status: {e}")
    
    return True

def check_and_train_model(user_email):
    """Check if ML model should be trained and train if conditions met"""
    with model_lock:
        if user_email not in user_models:
            user_models[user_email] = DeviceBehaviorModel(user_email)
        
        model = user_models[user_email]
    
    training_status = behavior_analyzer.get_training_status(user_email)
    
    if training_status and training_status.get('is_trained'):
        model_path = f"models/{user_email}_model.pkl"
        if model.load_model(model_path):
            print(f"📂 Loaded trained model for {user_email}")
            return True
        else:
            behavior_analyzer.update_training_status(user_email, {
                'is_training': True,
                'is_trained': False,
                'training_samples': 0
            })
    
    user = users_collection.find_one({'email': user_email})
    device_count = len(user.get('devices', [])) if user else 0
    
    if device_count < 2:
        print(f"⏸️ ML Training paused for {user_email}: Only {device_count} device(s)")
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
            'training_samples': sample_count,
            'last_update': current_time
        })
        
        try:
            socketio.emit('ml_training_progress', {
                'samples': sample_count,
                'elapsed_minutes': elapsed_minutes,
                'target_minutes': 5,
                'message': f'Collecting behavior patterns: {sample_count}/30 samples'
            }, room=user_email)
        except Exception as e:
            print(f"⚠️ Could not emit training progress: {e}")
        
        if sample_count >= 30 or elapsed_minutes >= 5:
            print(f"🤖 Training ML model for {user_email} with {sample_count} samples...")
            
            device_patterns = {}
            for device_id in user.get('devices', []):
                pattern = behavior_analyzer.get_device_pattern(user_email, device_id)
                if pattern:
                    device_patterns[device_id] = pattern
            
            success, message = model.train_model(behavior_data, device_patterns)
            
            if success:
                model_path = f"models/{user_email}_model.pkl"
                os.makedirs("models", exist_ok=True)
                model.save_model(model_path)
                
                behavior_analyzer.update_training_status(user_email, {
                    'is_training': False,
                    'is_trained': True,
                    'training_completed': datetime.datetime.utcnow(),
                    'training_samples': sample_count,
                    'model_path': model_path,
                    'model_info': model.get_model_info()
                })
                
                print(f"✅ ML Model trained successfully for {user_email}")
                
                try:
                    socketio.emit('ml_training_complete', {
                        'message': 'Security system activated!',
                        'samples': sample_count,
                        'model_info': model.get_model_info()
                    }, room=user_email)
                except Exception as e:
                    print(f"⚠️ Could not emit training complete: {e}")
                
                return True
            else:
                print(f"❌ ML Training failed for {user_email}: {message}")
                return False
        else:
            remaining_samples = max(0, 30 - sample_count)
            print(f"⏳ ML Training for {user_email}: {sample_count}/30 samples")
            return False
    
    return False

def analyze_device_behavior(user_email, device_locations):
    """Analyze device behavior and detect anomalies"""
    if len(device_locations) < 2:
        return None
    
    # ✅ CRITICAL FIX: Validate all device IDs before processing
    valid_device_locations = {}
    for dev_id, location in device_locations.items():
        if validate_device_id(dev_id):
            valid_device_locations[dev_id] = location
        else:
            print(f"⚠️ Skipping invalid device_id in ML analysis: {dev_id}")
    
    if len(valid_device_locations) < 2:
        return None
    
    university_data = university_collection.find_one({'user_email': user_email})
    if not university_data or 'sections' not in university_data:
        return None
    
    sections = university_data['sections']
    device_list = list(valid_device_locations.values())
    
    meaningful_movement = False
    for device in device_list:
        last_loc = locations_collection.find_one(
            {'device_id': device['device_id']},
            sort=[('timestamp', -1), ('_id', -1)]
        )
        
        if last_loc and 'latitude' in last_loc:
            distance = calculate_distance(
                last_loc['latitude'], last_loc['longitude'],
                device['latitude'], device['longitude']
            )
            if distance > 3.0:
                meaningful_movement = True
                break
    
    if not meaningful_movement:
        print(f"⏭️ Skipping ML analysis (no meaningful movement)")
        return None
    
    for i in range(len(device_list)):
        for j in range(i + 1, len(device_list)):
            device1 = device_list[i]
            device2 = device_list[j]
            
            # ✅ Validate device IDs again
            if not validate_device_id(device1['device_id']) or not validate_device_id(device2['device_id']):
                print(f"⚠️ Skipping invalid device pair: {device1['device_id']}, {device2['device_id']}")
                continue
            
            device1_section = detect_section(device1['latitude'], device1['longitude'], sections)
            device2_section = detect_section(device2['latitude'], device2['longitude'], sections)
            
            device1['current_section'] = device1_section
            device2['current_section'] = device2_section
            
            behavior_record = behavior_analyzer.analyze_device_pair(user_email, device1, device2)
            
            model_ready = check_and_train_model(user_email)
            
            if model_ready:
                with model_lock:
                    if user_email in user_models:
                        model = user_models[user_email]
                        
                        is_anomaly, confidence, message, anomaly_details = model.predict_anomaly(behavior_record)
                        
                        if is_anomaly:
                            print(f"🚨 ANOMALY DETECTED for {user_email}!")
                            print(f"   Score: {anomaly_details['score']:.3f}")
                            print(f"   Device 1: {device1_section}")
                            print(f"   Device 2: {device2_section}")
                            print(f"   Distance: {behavior_record['distance_between_devices']:.1f}m")
                            print(f"   Confidence: {confidence:.2f}")
                            
                            device1_pattern = behavior_analyzer.get_device_pattern(user_email, device1['device_id'])
                            device2_pattern = behavior_analyzer.get_device_pattern(user_email, device2['device_id'])
                            
                            device1_anomaly, device1_details = model.detect_individual_anomaly(
                                {'section_id': behavior_analyzer.get_section_id(device1_section),
                                 'speed': behavior_record.get('movement_speed_device1', 0)},
                                {'section_id': behavior_analyzer.get_section_id(device2_section),
                                 'distance_to_other': behavior_record['distance_between_devices'],
                                 'with_other_device': device2['device_id']}
                            )
                            
                            device2_anomaly, device2_details = model.detect_individual_anomaly(
                                {'section_id': behavior_analyzer.get_section_id(device2_section),
                                 'speed': behavior_record.get('movement_speed_device2', 0)},
                                {'section_id': behavior_analyzer.get_section_id(device1_section),
                                 'distance_to_other': behavior_record['distance_between_devices'],
                                 'with_other_device': device1['device_id']}
                            )
                            
                            alert_data = {
                                'message': 'Unusual device behavior detected!',
                                'device1': device1['device_id'],
                                'device2': device2['device_id'],
                                'device1_section': device1_section,
                                'device2_section': device2_section,
                                'distance': behavior_record['distance_between_devices'],
                                'confidence': confidence,
                                'score': anomaly_details['score'],
                                'threshold': anomaly_details['threshold'],
                                'cluster_distance': anomaly_details.get('cluster_distance', 0),
                                'timestamp': datetime.datetime.utcnow().isoformat(),
                                'details': {
                                    'pair_anomaly': True,
                                    'device1_anomaly': device1_anomaly,
                                    'device2_anomaly': device2_anomaly,
                                    'device1_reasons': device1_details.get('reasons', []) if device1_anomaly else [],
                                    'device2_reasons': device2_details.get('reasons', []) if device2_anomaly else [],
                                    'feature_analysis': anomaly_details.get('features', {})
                                }
                            }
                            
                            try:
                                socketio.emit('anomaly_alert', alert_data, room=user_email)
                            except Exception as e:
                                print(f"⚠️ Could not emit anomaly alert: {e}")
                            
                            if device1_anomaly and device1_details.get('reasons'):
                                try:
                                    socketio.emit('individual_anomaly', {
                                        'device_id': device1['device_id'],
                                        'reasons': device1_details['reasons'],
                                        'confidence': device1_details.get('confidence', 0.7),
                                        'timestamp': datetime.datetime.utcnow().isoformat()
                                    }, room=user_email)
                                except Exception as e:
                                    print(f"⚠️ Could not emit individual anomaly: {e}")
                            
                            if device2_anomaly and device2_details.get('reasons'):
                                try:
                                    socketio.emit('individual_anomaly', {
                                        'device_id': device2['device_id'],
                                        'reasons': device2_details['reasons'],
                                        'confidence': device2_details.get('confidence', 0.7),
                                        'timestamp': datetime.datetime.utcnow().isoformat()
                                    }, room=user_email)
                                except Exception as e:
                                    print(f"⚠️ Could not emit individual anomaly: {e}")

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

# ================ UPDATED WEB SOCKET HANDLERS ================

@socketio.on('connect')
def handle_connect():
    try:
        print(f"🔌 New WebSocket connection attempt: {request.sid}")
        
        # ✅ CRITICAL FIX: Use enhanced device_id extraction
        device_id = extract_device_id_from_request()
        
        # Additional debugging
        print(f"🔧 Connection details:")
        print(f"  - Socket ID: {request.sid}")
        print(f"  - Device ID from extract: {device_id[:20] if device_id else 'None'}")
        print(f"  - Request args: {dict(request.args)}")
        
        if hasattr(request, 'environ'):
            print(f"  - Query string: {request.environ.get('QUERY_STRING', 'None')}")
        
        if not device_id:
            print(f"⚠️ Client {request.sid} connected without device_id in handshake")
            print(f"ℹ️ This is OK - device_id will come from join_room event")
        
        # ✅ FIX: Store connection info in database (not session)
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
            print(f"✅ Stored connection for device: {device_id[:20] if device_id else 'None'}")
        
        print(f"✅ Client connected: {request.sid}")
        
        emit('connected', {
            'message': 'Connected to server',
            'sid': request.sid,
            'device_id': device_id,
            'status': 'ready_for_join'
        })
        
    except Exception as e:
        print(f'❌ Connect error: {e}')
        traceback.print_exc()
        emit('connection_error', {'message': str(e)})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'⚠️ Client disconnected: {request.sid}')
    
    try:
        connection = device_connections_collection.find_one({'socket_id': request.sid})
        if connection:
            device_id = connection['device_id']
            user_email = connection.get('user_email')
            
            device_connections_collection.delete_one({'socket_id': request.sid})
            print(f"🗑️ Removed connection for device {device_id[:8] if device_id else 'unknown'}...")
            
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
                    print(f"⚠️ Could not emit device offline: {e}")
                
    except Exception as e:
        print(f"⚠️ Error cleaning up device connection: {e}")

@socketio.on_error()
def handle_error(e):
    print(f'❌ Socket.IO error: {e}')
    traceback.print_exc()

@socketio.on('join_room')
def handle_join_room(data):
    """Handle device joining user room - FIXED: NO AUTO-DEVICE CREATION"""
    try:
        print(f"🎯 JOIN_ROOM event received from {request.sid}")
        print(f"📦 Data received: {data}")
        
        user_email = data.get('user_email')
        device_id = data.get('device_id')
        token = data.get('token')
        
        # ✅ CRITICAL FIX: Get device_id from database connection if not in data
        if not device_id or device_id == 'null':
            connection = device_connections_collection.find_one({'socket_id': request.sid})
            if connection:
                device_id = connection.get('device_id')
                print(f"🔄 Using device_id from connection: {device_id[:20] if device_id else 'null'}")
        
        # ✅ HARD VALIDATION: Still no device_id? Fail
        if not device_id or device_id == 'null':
            print(f"❌ No device_id provided in join_room for {request.sid}")
            emit('join_error', {
                'message': 'Device ID required. Please reconnect or refresh.',
                'code': 'DEVICE_ID_MISSING'
            })
            return
        
        # Validate device_id format
        if not validate_device_id(device_id):
            print(f"❌ Invalid device_id format: {device_id}")
            emit('join_error', {
                'message': 'Invalid Device ID format',
                'code': 'DEVICE_ID_INVALID'
            })
            return
        
        if not user_email:
            print("❌ No user_email provided for join_room")
            emit('join_error', {'message': 'User email required'})
            return
        
        # Verify token
        if token:
            try:
                if token.startswith('Bearer '):
                    token = token.split(' ')[1]
                jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            except Exception as e:
                print(f"⚠️ Token verification failed: {e}")
                emit('join_error', {'message': 'Invalid token'})
                return
        
        print(f"🔑 Join attempt - User: {user_email}, Device: {device_id[:20]}")
        
        # ✅ CRITICAL FIX: CHECK IF DEVICE EXISTS - DO NOT AUTO-CREATE
        device_exists = devices_collection.find_one({'device_id': device_id})
        
        if not device_exists:
            print(f"⚠️ Device {device_id[:20]} not registered yet - waiting for explicit add-device")
            emit('join_error', {
                'message': 'Device not registered. Please add device first.',
                'code': 'DEVICE_NOT_REGISTERED',
                'device_id': device_id
            })
            return  # ✅ STOP HERE - Don't create device
        
        # Verify device belongs to this user
        if device_exists['user_email'] != user_email:
            print(f"❌ Device {device_id[:20]} belongs to {device_exists['user_email']}, not {user_email}")
            emit('join_error', {
                'message': 'Device registered to another account',
                'code': 'DEVICE_WRONG_USER'
            })
            return
        
        print(f"✅ Device {device_id[:20]} properly registered to {user_email}")
        
        # ✅ Track connection with user_email
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
        
        # Update in-memory tracking
        connected_devices[device_id] = request.sid
        
        if user_email not in user_devices:
            user_devices[user_email] = set()
        user_devices[user_email].add(device_id)
        
        # Join the room
        join_room(user_email)
        print(f'✅ Device {device_id[:20]} for user {user_email} joined room')
        
        # Get device info
        device_info = devices_collection.find_one({'device_id': device_id})
        device_name = device_info.get('device_name', 'Unknown Device') if device_info else 'Unknown Device'
        device_os = device_info.get('os', 'Unknown') if device_info else 'Unknown'
        
        # Update device_locations with connection info
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
        
        # Send join confirmation
        emit('join_confirmation', {
            'message': f'Joined room for {user_email}',
            'user_email': user_email,
            'device_id': device_id,
            'device_name': device_name,
            'device_os': device_os
        })
        
        # Load and send existing locations for this user
        try:
            user = users_collection.find_one({'email': user_email})
            if user and 'devices' in user:
                for dev_id in user['devices']:
                    if not validate_device_id(dev_id):
                        continue
                    
                    # Try to get location from device_locations collection
                    location = device_locations_collection.find_one(
                        {'device_id': dev_id},
                        {'_id': 0}
                    )
                    
                    if not location:
                        # Fallback to locations collection
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
                        print(f"📡 Sent location for device {dev_id[:20]}")
            
        except Exception as e:
            print(f"⚠️ Error sending initial locations: {e}")
            traceback.print_exc()
        
        # Send ML status
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
                print(f"⚠️ Could not emit ML status: {e}")
        else:
            user = users_collection.find_one({'email': user_email})
            if user and len(user.get('devices', [])) >= 2:
                try:
                    emit('ml_status_update', {
                        'is_training': False,
                        'is_trained': False,
                        'training_samples': 0,
                        'message': 'Ready to start ML training with 2+ devices'
                    })
                except Exception as e:
                    print(f"⚠️ Could not emit ML ready status: {e}")
        
        # Notify other devices
        try:
            socketio.emit('device_connected', {
                'device_id': device_id,
                'device_name': device_name,
                'os': device_os,
                'timestamp': datetime.datetime.utcnow().isoformat()
            }, room=user_email)
        except Exception as e:
            print(f"⚠️ Could not emit device connected: {e}")
            
        print(f"✅ Join process completed successfully for {user_email}")
            
    except Exception as e:
        print(f"❌ Error in join_room: {str(e)}")
        traceback.print_exc()
        emit('join_error', {'message': str(e)})

@socketio.on('update_location')
def handle_location_update(data):
    """Handle location updates - SIMPLIFIED AND FIXED"""
    try:
        print(f"📍 UPDATE_LOCATION event received from {request.sid}")
        print(f"📦 Location data: {data}")
        
        device_id = data.get('device_id')
        user_email = data.get('user_email')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        accuracy = data.get('accuracy', 0)
        
        # ✅ CRITICAL: If device_id missing, get from connection tracking
        if not device_id or device_id == 'null':
            connection = device_connections_collection.find_one({'socket_id': request.sid})
            if connection:
                device_id = connection.get('device_id')
                user_email = connection.get('user_email', user_email)
                print(f"🔄 Using connection-tracked device_id: {device_id[:20] if device_id else 'null'}")
        
        # ✅ Validate all required fields
        if not all([device_id, user_email, latitude, longitude]):
            print(f"❌ Missing required fields for location update")
            print(f"   device_id: {device_id}, user_email: {user_email}")
            print(f"   lat: {latitude}, lon: {longitude}")
            emit('location_error', {'message': 'Missing required fields'})
            return
        
        if not validate_device_id(device_id):
            print(f"❌ Invalid device_id: {device_id}")
            emit('location_error', {'message': 'Invalid Device ID'})
            return
        
        print(f"📍 Processing location for device: {device_id[:20]}")
        
        # Convert values
        try:
            raw_lat = float(latitude)
            raw_lng = float(longitude)
            acc = float(accuracy)
        except ValueError as e:
            print(f"❌ Invalid coordinate format: {e}")
            return
        
        # Validate and constrain location
        validated_lat, validated_lng, validated_acc, is_valid, reason = validate_and_constrain_location(
            device_id, raw_lat, raw_lng, acc
        )
        
        if not is_valid:
            print(f"⚠️ Location rejected: {reason}")
            try:
                socketio.emit('location_rejected', {
                    'device_id': device_id,
                    'reason': reason,
                    'original_accuracy': acc
                }, room=user_email)
            except Exception as e:
                print(f"⚠️ Could not emit location rejected: {e}")
            return
        
        current_time = datetime.datetime.utcnow()
        
        # Get device info
        device_info = devices_collection.find_one({'device_id': device_id})
        device_name = device_info.get('device_name', 'Unknown Device') if device_info else 'Unknown Device'
        device_os = device_info.get('os', 'Unknown') if device_info else 'Unknown'
        
        # Detect section
        university_data = university_collection.find_one({'user_email': user_email})
        current_section = 'Outside Campus'
        if university_data and 'sections' in university_data:
            current_section = detect_section(validated_lat, validated_lng, university_data['sections'])
        
        # Store in locations collection
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
        
        # Update device_locations for real-time tracking
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
        
        # Update device info
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
        
        # Broadcast to all devices in the room
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
            print(f"✅ Location update sent for device {device_id[:20]}")
        except Exception as e:
            print(f"⚠️ Could not emit location update: {e}")
        
        # ML analysis if we have 2+ devices
        user = users_collection.find_one({'email': user_email})
        if user and len(user.get('devices', [])) >= 2:
            # Simple ML trigger - in production you'd want more sophisticated logic
            try:
                user_devices_locations = {}
                for dev_id in user.get('devices', []):
                    if not validate_device_id(dev_id):
                        continue
                    
                    loc = device_locations_collection.find_one({'device_id': dev_id})
                    if loc:
                        user_devices_locations[dev_id] = loc
                
                if len(user_devices_locations) >= 2:
                    # Start ML analysis in background
                    import threading
                    thread = threading.Thread(
                        target=analyze_device_behavior,
                        args=(user_email, user_devices_locations)
                    )
                    thread.daemon = True
                    thread.start()
            except Exception as e:
                print(f"⚠️ ML analysis setup failed: {e}")
        
    except Exception as e:
        print(f"❌ Error in update_location: {str(e)}")
        traceback.print_exc()

# ================ REST API ENDPOINTS ================

@app.route('/')
def home():
    return jsonify({'message': 'Tracker API is running', 'status': 'online', 'timestamp': datetime.datetime.utcnow().isoformat()})

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        client.admin.command('ping')
        
        models_dir = 'models'
        model_count = 0
        if os.path.exists(models_dir):
            model_count = len([f for f in os.listdir(models_dir) if f.endswith('.pkl')])
        
        connected_count = len(connected_devices)
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'database': 'connected',
            'ml_models': model_count,
            'active_users': len(user_models),
            'connected_devices': connected_count,
            'device_locations_count': len(device_locations),
            'server': 'running',
            'version': '1.0.0',
            'websocket_support': True,
            'cache_size': len(last_location_cache),
            'multi_device_support': True,
            'device_id_fix': 'APPLIED_V3',
            'no_auto_device_creation': True  # ✅ Added flag
        }), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# ================ UPDATED REGISTRATION - NO DEVICE REGISTRATION ================

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        # ✅ NO device_id or device_info required
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        if users_collection.find_one({'email': email}):
            return jsonify({'error': 'User already exists'}), 400
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # ✅ Create user account ONLY - NO devices
        user = {
            'email': email,
            'password': hashed_password,
            'created_at': datetime.datetime.utcnow(),
            'devices': [],  # Empty devices list
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
        
        print(f"✅ User account created: {email}")
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': serialize_document(user)
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ================ UPDATED LOGIN - NO DEVICE REGISTRATION ================

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        # ✅ NO device_id or device_info required
        
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
        
        print(f"✅ User logged in: {email}")
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': user_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ================ UPDATED CHECK-DEVICE - PROPER DEVICE DETECTION ================

@app.route('/api/check-device', methods=['GET'])
@token_required
def check_device(current_user):
    try:
        device_id = request.headers.get('X-Device-ID') or request.args.get('device_id')
        
        if not device_id:
            # Generate fallback device ID
            user_agent = request.headers.get('User-Agent', '')
            system_info = f"{platform.system()}{platform.release()}{platform.machine()}"
            fingerprint_string = system_info + user_agent
            device_id = hashlib.sha256(fingerprint_string.encode()).hexdigest()
            print(f"⚠️ Using fallback device ID: {device_id[:20]}...")
        
        # Check if device exists anywhere in the system
        device = devices_collection.find_one({'device_id': device_id})
        
        # Check if current user has this device
        user = users_collection.find_one({'email': current_user['email']})
        user_has_device = device_id in user.get('devices', []) if user else False
        
        user_agent = request.headers.get('User-Agent', '')
        os = detect_os(user_agent)
        
        device_status = 'not_registered'
        device_owner = None
        
        if device:
            if device['user_email'] == current_user['email']:
                device_status = 'registered_to_me'
                device_owner = current_user['email']
            else:
                device_status = 'registered_to_other'
                device_owner = device['user_email']
        
        print(f"🔍 Device check: {device_id[:20]}... - Status: {device_status}")
        
        return jsonify({
            'device_id': device_id,
            'device_exists': device is not None,
            'user_has_device': user_has_device,
            'device_status': device_status,
            'device_owner': device_owner,
            'os': os,
            'location_permission': user.get('location_permission', False) if user else False
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ================ ADD-DEVICE ENDPOINT - WITH PROPER VALIDATION ================

@app.route('/api/add-device', methods=['POST'])
@token_required
def add_device(current_user):
    try:
        data = request.json
        device_id = data.get('device_id')
        device_name = data.get('device_name', 'My Device')
        
        if not device_id or not validate_device_id(device_id):
            return jsonify({'error': 'Valid Device ID is required'}), 400
        
        # Check if device already exists in system
        existing_device = devices_collection.find_one({'device_id': device_id})
        
        if existing_device:
            if existing_device['user_email'] == current_user['email']:
                return jsonify({'error': 'Device already in your account'}), 400
            else:
                return jsonify({
                    'error': 'Device already registered to another account',
                    'owner': existing_device['user_email']
                }), 400
        
        # Check if user already has this device in their list
        user = users_collection.find_one({'email': current_user['email']})
        if device_id in user.get('devices', []):
            return jsonify({'error': 'Device already in your account'}), 400
        
        user_agent = request.headers.get('User-Agent', 'Unknown')
        os = detect_os(user_agent)
        browser = detect_browser(user_agent)
        
        # Create device record
        device = {
            'device_id': device_id,
            'device_name': device_name,
            'user_email': current_user['email'],
            'added_at': datetime.datetime.utcnow(),
            'os': os,
            'browser': browser,
            'user_agent': user_agent,
            'last_seen': datetime.datetime.utcnow(),
            'location_tracking': False,  # Will be enabled when permission granted
            'current_section': 'Outside Campus'
        }
        
        result = devices_collection.insert_one(device)
        device['_id'] = str(result.inserted_id)
        
        # Add device to user's devices list
        users_collection.update_one(
            {'email': current_user['email']},
            {'$push': {'devices': device_id}}
        )
        
        print(f"✅ Device added: {device_id[:20]}... to {current_user['email']}")
        
        device_status = {
            'device_id': device_id,
            'device_exists': True,
            'user_has_device': True,
            'device_status': 'registered_to_me',
            'device_owner': current_user['email'],
            'os': os
        }
        
        # Check if ML training should start
        updated_user = users_collection.find_one({'email': current_user['email']})
        device_count = len(updated_user.get('devices', []))
        
        ml_training_started = False
        if device_count >= 2:
            print(f"🤖 User has {device_count} devices - ML training can start")
            ml_training_started = True
        
        return jsonify({
            'message': 'Device added successfully',
            'device': serialize_document(device),
            'device_status': device_status,
            'ml_training_started': ml_training_started,
            'device_count': device_count
        }), 201
        
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
                print(f"🏛️ University created at {center_lat}, {center_lon}")
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
        print(f"📌 Loading locations for user: {current_user['email']}")
        
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
        
        print(f"📌 Returning {len(all_locations)} live locations")
        return jsonify({
            'locations': all_locations
        }), 200
        
    except Exception as e:
        print(f"❌ Error loading locations: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/ml-status', methods=['GET'])
@token_required
def get_ml_status(current_user):
    try:
        training_status = behavior_analyzer.get_training_status(current_user['email'])
        
        if not training_status:
            user = users_collection.find_one({'email': current_user['email']})
            device_count = len(user.get('devices', [])) if user else 0
            
            status = {
                'is_training': False,
                'is_trained': False,
                'training_samples': 0,
                'device_count': device_count,
                'can_start_training': device_count >= 2
            }
            
            if device_count >= 2:
                status['message'] = 'Ready to start ML training. Add location permission to begin.'
            else:
                status['message'] = f'Add {2 - device_count} more device(s) to start ML training'
            
            return jsonify(status), 200
        
        model_info = {}
        if training_status.get('is_trained') and current_user['email'] in user_models:
            with model_lock:
                model = user_models[current_user['email']]
                model_info = model.get_model_info()
        
        response = {
            'is_training': training_status.get('is_training', False),
            'is_trained': training_status.get('is_trained', False),
            'training_samples': training_status.get('training_samples', 0),
            'training_started': training_status.get('training_started', '').isoformat() if training_status.get('training_started') else None,
            'training_completed': training_status.get('training_completed', '').isoformat() if training_status.get('training_completed') else None,
            'model_info': model_info,
            'message': training_status.get('message', '')
        }
        
        if training_status.get('is_training'):
            training_started = training_status.get('training_started')
            if training_started:
                elapsed = (datetime.datetime.utcnow() - training_started).total_seconds() / 60
                remaining = max(0, 5 - elapsed)
                response['elapsed_minutes'] = round(elapsed, 1)
                response['remaining_minutes'] = round(remaining, 1)
                response['progress_percentage'] = min(100, int((elapsed / 5) * 100))
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/start-ml-training', methods=['POST'])
@token_required
def start_ml_training_route(current_user):
    try:
        user = users_collection.find_one({'email': current_user['email']})
        device_count = len(user.get('devices', [])) if user else 0
        
        if device_count < 2:
            return jsonify({
                'success': False,
                'message': f'Need 2+ devices to start ML training. Currently have {device_count}.'
            }), 400
        
        training_status = behavior_analyzer.get_training_status(current_user['email'])
        if training_status and (training_status.get('is_training') or training_status.get('is_trained')):
            return jsonify({
                'success': False,
                'message': 'ML training already in progress or completed'
            }), 400
        
        success = start_ml_training(current_user['email'])
        
        if success:
            return jsonify({
                'success': True,
                'message': 'ML training started successfully. Will train for 5 minutes.',
                'estimated_completion': (datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).isoformat()
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start ML training'
            }), 500
            
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
        for device_id in user.get('devices', []):
            pattern = behavior_analyzer.get_device_pattern(current_user['email'], device_id)
            if pattern:
                pattern.pop('_id', None)
                
                if 'section_visits' in pattern:
                    total_visits = sum(pattern['section_visits'].values())
                    pattern['section_percentages'] = {
                        section: (count / total_visits * 100) if total_visits > 0 else 0
                        for section, count in pattern['section_visits'].items()
                    }
                
                device_patterns[device_id] = pattern
        
        return jsonify({
            'patterns': device_patterns,
            'device_count': len(device_patterns)
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
        behavior_count = behavior_analyzer.behavior_collection.count_documents({})
        connected_devices_count = device_connections_collection.count_documents({'is_online': True})
        
        models_dir = 'models'
        trained_models = 0
        if os.path.exists(models_dir):
            trained_models = len([f for f in os.listdir(models_dir) if f.endswith('.pkl')])
        
        return jsonify({
            'status': 'online',
            'users': user_count,
            'devices': device_count,
            'active_locations': location_count,
            'behavior_records': behavior_count,
            'trained_ml_models': trained_models,
            'active_ml_models': len(user_models),
            'connected_devices': connected_devices_count,
            'cache_size': len(last_location_cache),
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'multi_device_active': True,
            'device_id_fix': 'APPLIED_V3',
            'no_auto_device_creation': True  # ✅ Added flag
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

@app.route('/api/connected-devices', methods=['GET'])
@token_required
def get_connected_devices(current_user):
    try:
        connected_devices_list = list(device_connections_collection.find(
            {'user_email': current_user['email'], 'is_online': True},
            {'_id': 0, 'device_id': 1, 'connected_at': 1, 'socket_id': 1}
        ))
        
        for device in connected_devices_list:
            device_info = devices_collection.find_one(
                {'device_id': device['device_id']},
                {'device_name': 1, 'os': 1, '_id': 0}
            )
            if device_info:
                device.update(device_info)
        
        return jsonify({
            'connected_devices': connected_devices_list,
            'count': len(connected_devices_list)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ================ ADDITIONAL DEBUGGING ENDPOINTS ================

@app.route('/api/test-device-id', methods=['GET'])
@token_required
def test_device_id(current_user):
    """Test endpoint to check device_id extraction"""
    device_id = extract_device_id_from_request()
    
    return jsonify({
        'device_id_from_extract': device_id,
        'device_id_valid': validate_device_id(device_id),
        'request_args': dict(request.args),
        'request_headers': dict(request.headers),
        'socket_id': request.sid if hasattr(request, 'sid') else None,
        'user_email': current_user['email']
    })

@app.route('/api/simulate-location', methods=['POST'])
@token_required
def simulate_location(current_user):
    """Simulate a location update for testing"""
    try:
        data = request.json
        device_id = data.get('device_id')
        latitude = data.get('latitude', 40.7128)
        longitude = data.get('longitude', -74.0060)
        accuracy = data.get('accuracy', 10)
        
        if not device_id:
            # Use first device of user
            user = users_collection.find_one({'email': current_user['email']})
            if user and 'devices' in user and len(user['devices']) > 0:
                device_id = user['devices'][0]
            else:
                return jsonify({'error': 'No device found for user'}), 400
        
        # Create simulated location update
        update_data = {
            'device_id': device_id,
            'user_email': current_user['email'],
            'latitude': latitude,
            'longitude': longitude,
            'accuracy': accuracy
        }
        
        # Trigger location update via WebSocket if connected
        connection = device_connections_collection.find_one({
            'device_id': device_id,
            'user_email': current_user['email'],
            'is_online': True
        })
        
        if connection:
            socket_id = connection.get('socket_id')
            try:
                socketio.emit('update_location', update_data, room=socket_id)
                return jsonify({
                    'success': True,
                    'message': 'Location simulation sent via WebSocket',
                    'data': update_data
                })
            except Exception as e:
                return jsonify({
                    'success': False,
                    'message': f'WebSocket error: {str(e)}',
                    'data': update_data
                })
        else:
            # Manual update
            current_time = datetime.datetime.utcnow()
            
            device_locations_collection.update_one(
                {'device_id': device_id},
                {
                    '$set': {
                        'device_id': device_id,
                        'device_name': 'Test Device',
                        'os': 'Test',
                        'latitude': latitude,
                        'longitude': longitude,
                        'accuracy': accuracy,
                        'user_email': current_user['email'],
                        'current_section': 'Outside Campus',
                        'timestamp': current_time,
                        'is_online': True
                    }
                },
                upsert=True
            )
            
            return jsonify({
                'success': True,
                'message': 'Location simulation stored in database',
                'data': update_data
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/force-connect', methods=['POST'])
@token_required
def force_connect(current_user):
    """Force reconnection for testing"""
    device_id = request.json.get('device_id')
    if not device_id:
        return jsonify({'error': 'Device ID required'}), 400
    
    # Clean up any existing connection
    device_connections_collection.delete_one({'device_id': device_id})
    
    return jsonify({
        'success': True,
        'message': 'Connection cleaned up. Please reconnect from frontend.',
        'device_id': device_id
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    os.makedirs("models", exist_ok=True)
    
    print(f"🚀 Starting server on port {port}")
    print(f"📍 Location validation settings:")
    print(f"   - High accuracy threshold: < {HIGH_ACCURACY_THRESHOLD}m")
    print(f"   - Maximum acceptable accuracy: < {MAX_ACCEPTABLE_ACCURACY}m")
    print(f"   - Maximum position drift: {MAX_POSITION_DRIFT}m")
    print(f"🏛️ University system enabled - 12x12 meter sections")
    print(f"🤖 ENHANCED ML Anomaly Detection: Active")
    print(f"🌐 WebSocket enabled with threading mode")
    print(f"🛡️ CRITICAL DEVICE REGISTRATION FIX APPLIED:")
    print(f"   - REMOVED auto-device creation from join_room handler")
    print(f"   - Devices ONLY created via /api/add-device endpoint")
    print(f"   - join_room now validates device exists and belongs to user")
    print(f"   - No more duplicate device entries")
    print(f"✅ FIXED REGISTRATION & LOGIN FLOW:")
    print(f"   - Registration: Creates user account ONLY (no device)")
    print(f"   - Login: NO automatic device registration")
    print(f"   - Device check: Detects if device needs to be added")
    print(f"   - Add device: Proper validation and permission flow")
    print(f"🔍 Device workflow:")
    print(f"   1. User registers → Account created (no device)")
    print(f"   2. User logs in → Dashboard loads")
    print(f"   3. Dashboard checks device → Shows add device form if needed")
    print(f"   4. User adds device via /api/add-device → Device created")
    print(f"   5. WebSocket join_room → Validates device registration")
    print(f"   6. Location permission requested → Tracking enabled")
    print(f"   7. 2+ devices → ML learning starts automatically")
    print(f"🔍 Debug endpoints available:")
    print(f"   - /api/test-device-id")
    print(f"   - /api/simulate-location")
    print(f"   - /api/force-connect")
    
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)