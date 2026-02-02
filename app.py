# app.py - UPDATED WITH DEVICE_ID FIXES
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
import uuid

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

def extract_device_id_from_request():
    """Extract device_id from WebSocket request"""
    try:
        # Method 1: From query params
        device_id = request.args.get('device_id')
        if device_id:
            return device_id
        
        # Method 2: From auth (for Socket.IO v4+)
        if hasattr(request, 'auth'):
            return request.auth.get('device_id') if request.auth else None
            
        # Method 3: From headers
        device_id = request.headers.get('X-Device-ID')
        if device_id:
            return device_id
            
        return None
        
    except Exception as e:
        print(f"⚠️ Error extracting device_id: {e}")
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

@socketio.on('connect')
def handle_connect():
    try:
        # ✅ CRITICAL FIX: Extract device_id from handshake
        device_id = extract_device_id_from_request()
        
        if not device_id:
            # Try to get from query string
            device_id = request.args.get('device_id')
        
        if not device_id:
            print(f'❌ Client connected without device_id: {request.sid}')
            device_id = f"temp_{request.sid[:10]}"
            print(f'⚠️ Assigned temporary device_id: {device_id}')
        
        print(f'✅ Client connected: {request.sid} | Device: {device_id[:12] if device_id else "null"}')
        
        # Store device_id in a way accessible to other handlers
        from flask import session
        session['device_id'] = device_id
        
        emit('connected', {
            'message': 'Connected to server',
            'sid': request.sid,
            'device_id': device_id
        })
        
    except Exception as e:
        print(f'❌ Connect error: {e}')
        emit('connection_error', {'message': str(e)})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'⚠️ Client disconnected: {request.sid}')
    
    try:
        connection = device_connections_collection.find_one({'socket_id': request.sid})
        if connection:
            device_id = connection['device_id']
            user_email = connection['user_email']
            
            device_connections_collection.delete_one({'socket_id': request.sid})
            print(f"🗑️ Removed connection for device {device_id[:8] if device_id else 'unknown'}...")
            
            device_locations_collection.update_one(
                {'device_id': device_id},
                {'$set': {'is_online': False, 'last_seen': datetime.datetime.utcnow()}},
                upsert=True
            )
            
            if device_id in connected_devices:
                del connected_devices[device_id]
            
            if user_email in user_devices and device_id in user_devices[user_email]:
                user_devices[user_email].remove(device_id)
            
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

@socketio.on('join_room')
def handle_join_room(data):
    try:
        user_email = data.get('user_email')
        device_id = data.get('device_id')
        token = data.get('token')
        
        # ✅ CRITICAL FIX: If device_id not provided, try multiple sources
        if not device_id or device_id == 'null':
            # Try from WebSocket handshake
            device_id = extract_device_id_from_request()
            
            # Try from existing connection
            if not device_id:
                connection = device_connections_collection.find_one({'socket_id': request.sid})
                if connection:
                    device_id = connection.get('device_id')
            
            # Try from session
            if not device_id:
                from flask import session
                device_id = session.get('device_id')
            
            # Last resort: generate temporary
            if not device_id or device_id == 'null':
                device_id = f"temp_{request.sid[:10]}"
                print(f"⚠️ Generated temporary device_id: {device_id}")
        
        # ✅ HARD VALIDATION
        if not validate_device_id(device_id):
            print(f"❌ JOIN ERROR: Invalid device_id: {device_id}")
            emit('join_error', {'message': 'Invalid Device ID'})
            return
        
        if not user_email:
            print("❌ No user_email provided for join_room")
            emit('join_error', {'message': 'User email required'})
            return
        
        # Verify token if provided
        if token:
            try:
                if token.startswith('Bearer '):
                    token = token.split(' ')[1]
                data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
                if data['email'] != user_email:
                    emit('join_error', {'message': 'Token email mismatch'})
                    return
            except Exception as e:
                print(f"⚠️ Token verification failed: {e}")
        
        # ✅ Track device connection
        device_connections_collection.update_one(
            {'device_id': device_id},
            {
                '$set': {
                    'socket_id': request.sid,
                    'user_email': user_email,
                    'device_id': device_id,
                    'connected_at': datetime.datetime.utcnow(),
                    'is_online': True
                }
            },
            upsert=True
        )
        
        # Update in-memory tracking
        connected_devices[device_id] = request.sid
        
        if user_email not in user_devices:
            user_devices[user_email] = set()
        user_devices[user_email].add(device_id)
        
        join_room(user_email)
        print(f'✅ Device {device_id[:8] if device_id else "unknown"}... for user {user_email} joined room')
        emit('join_confirmation', {
            'message': f'Joined room for {user_email}',
            'user_email': user_email,
            'device_id': device_id
        })
        
        # Update device_locations with connection info
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
        
        # Send all device locations for this user
        try:
            user = users_collection.find_one({'email': user_email})
            if user and 'devices' in user:
                for dev_id in user['devices']:
                    # ✅ Skip invalid device IDs
                    if not validate_device_id(dev_id):
                        continue
                        
                    location = locations_collection.find_one(
                        {'device_id': dev_id},
                        sort=[('timestamp', -1)]
                    )
                    
                    if location:
                        device = devices_collection.find_one({'device_id': dev_id})
                        device_name = device.get('device_name', 'Unknown') if device else 'Unknown'
                        device_os = device.get('os', 'Unknown') if device else 'Unknown'
                        
                        is_online = dev_id in connected_devices
                        
                        broadcast_data = {
                            'device_id': dev_id,
                            'device_name': device_name,
                            'os': device_os,
                            'latitude': location['latitude'],
                            'longitude': location['longitude'],
                            'accuracy': location.get('accuracy', 0),
                            'timestamp': location['timestamp'].isoformat(),
                            'validation_reason': location.get('validation_reason', 'unknown'),
                            'current_section': location.get('current_section', 'Outside Campus'),
                            'is_online': is_online
                        }
                        
                        socketio.emit('location_update', broadcast_data, room=user_email)
            
        except Exception as e:
            print(f"⚠️ Error sending initial locations: {e}")
        
        # Send ML status
        training_status = behavior_analyzer.get_training_status(user_email)
        if training_status:
            try:
                emit('ml_status_update', {
                    'is_training': training_status.get('is_training', False),
                    'is_trained': training_status.get('is_trained', False),
                    'training_samples': training_status.get('training_samples', 0),
                    'training_started': training_status.get('training_started', '').isoformat() if training_status.get('training_started') else None,
                    'training_completed': training_status.get('training_completed', '').isoformat() if training_status.get('training_completed') else None
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
                    
        # Notify other devices that new device joined
        try:
            socketio.emit('device_connected', {
                'device_id': device_id,
                'device_name': device_name,
                'os': device_os,
                'timestamp': datetime.datetime.utcnow().isoformat()
            }, room=user_email)
        except Exception as e:
            print(f"⚠️ Could not emit device connected: {e}")
            
    except Exception as e:
        print(f"❌ Error joining room: {str(e)}")
        emit('join_error', {'message': str(e)})

@socketio.on('update_location')
def handle_location_update(data):
    try:
        device_id = data.get('device_id')
        
        # ✅ CRITICAL FIX: If device_id missing, try to get from connection tracking
        if not device_id or device_id == 'null':
            # Try to find device_id from connection tracking
            connection = device_connections_collection.find_one({'socket_id': request.sid})
            if connection:
                device_id = connection.get('device_id')
                print(f"🔄 Using tracked device_id: {device_id[:8] if device_id else 'unknown'}...")
            else:
                # Try from session
                from flask import session
                device_id = session.get('device_id')
                
                if not device_id:
                    print(f"❌ No device_id found for socket {request.sid}")
                    emit('location_error', {'message': 'Device ID not found. Please reconnect.'})
                    return
        
        # ✅ HARD GUARD: Prevent null device_id processing
        if not validate_device_id(device_id):
            print(f"❌ REJECTED: Invalid device_id: {device_id}")
            emit('location_error', {'message': 'Invalid Device ID'})
            return
        
        print(f"📍 Received location update for device: {device_id[:8] if device_id else 'unknown'}")
        
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        accuracy = data.get('accuracy', 0)
        user_email = data.get('user_email')
        
        if not all([device_id, latitude, longitude, user_email]):
            print(f"❌ Missing required fields: device_id={device_id}, user_email={user_email}")
            return
        
        try:
            raw_lat = float(latitude)
            raw_lng = float(longitude)
            acc = float(accuracy)
        except ValueError as e:
            print(f"❌ Invalid coordinate format: {e}")
            return
        
        # Check cache for duplicate locations
        cache_key = f"{device_id}_{user_email}"
        current_time = datetime.datetime.utcnow()
        
        if cache_key in last_location_cache:
            last_data, last_time = last_location_cache[cache_key]
            time_diff = (current_time - last_time).total_seconds()
            
            if time_diff < CACHE_TTL:
                last_lat, last_lon, last_acc = last_data
                distance = calculate_distance(last_lat, last_lon, raw_lat, raw_lng)
                
                if distance < 2.0 and acc >= last_acc:
                    print(f"⏭️ Skipping duplicate location for {device_id[:8] if device_id else 'unknown'}...")
                    return
        
        # Update cache
        last_location_cache[cache_key] = ((raw_lat, raw_lng, acc), current_time)
        
        # Clean old cache entries
        cache_keys_to_delete = []
        for key in last_location_cache.keys():
            if (current_time - last_location_cache[key][1]).total_seconds() > 10:
                cache_keys_to_delete.append(key)
        
        for key in cache_keys_to_delete:
            del last_location_cache[key]
        
        # Update device_locations collection
        device_info = devices_collection.find_one({'device_id': device_id})
        device_name = device_info.get('device_name', 'Unknown Device') if device_info else 'Unknown Device'
        device_os = device_info.get('os', 'Unknown') if device_info else 'Unknown'
        
        # Validate and constrain
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
        
        university_data = university_collection.find_one({'user_email': user_email})
        current_section = 'Outside Campus'
        
        if university_data and 'sections' in university_data:
            current_section = detect_section(validated_lat, validated_lng, university_data['sections'])
            print(f"📌 Device {device_id[:8] if device_id else 'unknown'} in section: {current_section}")
        
        # Store raw location
        raw_location_data = {
            'device_id': device_id,
            'latitude': raw_lat,
            'longitude': raw_lng,
            'accuracy': acc,
            'timestamp': current_time,
            'user_email': user_email,
            'validation_reason': 'raw_location'
        }
        
        locations_collection.update_one(
            {'device_id': device_id, 'validation_reason': 'raw_location'},
            {'$set': raw_location_data},
            upsert=True
        )
        
        location_data = {
            'device_id': device_id,
            'latitude': validated_lat,
            'longitude': validated_lng,
            'accuracy': validated_acc,
            'raw_latitude': raw_lat,
            'raw_longitude': raw_lng,
            'raw_accuracy': acc,
            'timestamp': current_time,
            'user_email': user_email,
            'validation_reason': reason,
            'current_section': current_section
        }
        
        if reason == "high_accuracy_accepted":
            location_data['best_latitude'] = validated_lat
            location_data['best_longitude'] = validated_lng
            location_data['best_accuracy'] = validated_acc
            location_data['best_timestamp'] = current_time
        else:
            existing = locations_collection.find_one(
                {'device_id': device_id},
                sort=[('timestamp', -1)]
            )
            if existing and 'best_latitude' in existing:
                location_data['best_latitude'] = existing['best_latitude']
                location_data['best_longitude'] = existing['best_longitude']
                location_data['best_accuracy'] = existing['best_accuracy']
                location_data['best_timestamp'] = existing.get('best_timestamp', current_time)
        
        locations_collection.update_one(
            {'device_id': device_id, 'validation_reason': {'$ne': 'raw_location'}},
            {'$set': location_data},
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
        
        # Update in-memory location storage
        device_locations[device_id] = {
            'device_id': device_id,
            'device_name': device_name,
            'os': device_os,
            'latitude': validated_lat,
            'longitude': validated_lng,
            'accuracy': validated_acc,
            'timestamp': current_time,
            'current_section': current_section,
            'is_online': True
        }
        
        broadcast_data = {
            'device_id': device_id,
            'device_name': device_name,
            'os': device_os,
            'latitude': validated_lat,
            'longitude': validated_lng,
            'accuracy': validated_acc,
            'timestamp': location_data['timestamp'].isoformat(),
            'validation_reason': reason,
            'current_section': current_section,
            'is_online': True
        }
        
        try:
            socketio.emit('location_update', broadcast_data, room=user_email)
            print(f"✅ Location update sent for device {device_id[:8] if device_id else 'unknown'}")
        except Exception as e:
            print(f"⚠️ Could not emit location update: {e}")
        
        # ML analysis
        user = users_collection.find_one({'email': user_email})
        if user and len(user.get('devices', [])) >= 2:
            last_meaningful_location = locations_collection.find_one(
                {'device_id': device_id, 'validation_reason': {'$ne': 'raw_location'}},
                sort=[('timestamp', -1)]
            )
            
            should_analyze = True
            if last_meaningful_location:
                distance_moved = calculate_distance(
                    last_meaningful_location.get('latitude', validated_lat),
                    last_meaningful_location.get('longitude', validated_lng),
                    validated_lat,
                    validated_lng
                )
                
                if distance_moved < 3.0:
                    should_analyze = False
                    print(f"⏭️ Skipping ML analysis (minimal movement: {distance_moved:.1f}m)")
            
            if should_analyze:
                user_devices_locations = {}
                for dev_id in user.get('devices', []):
                    # ✅ Skip invalid device IDs
                    if not validate_device_id(dev_id):
                        continue
                        
                    loc = locations_collection.find_one(
                        {'device_id': dev_id, 'validation_reason': {'$ne': 'raw_location'}},
                        sort=[('timestamp', -1)]
                    )
                    if loc and 'latitude' in loc:
                        user_devices_locations[dev_id] = loc
                
                if len(user_devices_locations) >= 2:
                    analyze_device_behavior(user_email, user_devices_locations)
        
    except Exception as e:
        print(f"❌ Error updating location: {str(e)}")
        import traceback
        traceback.print_exc()

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
            'device_id_fix': 'APPLIED'  # ✅ Added to confirm fix
        }), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        device_id = data.get('device_id')
        device_info = data.get('device_info', {})
        
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
        
        if device_id:
            try:
                device_os = device_info.get('os', 'Unknown')
                user_agent = device_info.get('userAgent', 'Unknown')
                
                device = {
                    'device_id': device_id,
                    'device_name': f"{device_os} Device",
                    'user_email': email,
                    'added_at': datetime.datetime.utcnow(),
                    'os': device_os,
                    'browser': detect_browser(user_agent),
                    'user_agent': user_agent,
                    'last_seen': datetime.datetime.utcnow(),
                    'location_tracking': False,
                    'current_section': 'Outside Campus'
                }
                
                devices_collection.insert_one(device)
                users_collection.update_one(
                    {'email': email},
                    {'$push': {'devices': device_id}}
                )
                
                print(f"📱 Device registered during registration: {device_id[:8] if device_id else 'unknown'}...")
            except Exception as e:
                print(f"⚠️ Device registration during signup failed: {e}")
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': serialize_document(user),
            'device_registered': device_id is not None
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        device_id = data.get('device_id')
        device_info = data.get('device_info', {})
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = users_collection.find_one({'email': email})
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not bcrypt.check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        device_exists = False
        if device_id:
            device_exists = devices_collection.find_one({'device_id': device_id}) is not None
            
            if not device_exists:
                print(f"📱 New device detected during login: {device_id[:8] if device_id else 'unknown'}...")
        
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
            'user': user_data,
            'device_exists': device_exists,
            'device_id': device_id,
            'needs_device_registration': device_id and not device_exists
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-device', methods=['GET'])
@token_required
def check_device(current_user):
    try:
        device_id = request.headers.get('X-Device-ID') or request.args.get('device_id')
        
        if not device_id:
            user_agent = request.headers.get('User-Agent', '')
            system_info = f"{platform.system()}{platform.release()}{platform.machine()}"
            fingerprint_string = system_info + user_agent
            device_id = hashlib.sha256(fingerprint_string.encode()).hexdigest()
            print(f"⚠️ Using fallback device ID: {device_id[:8]}...")
        
        device = devices_collection.find_one({'device_id': device_id})
        
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

@app.route('/api/add-device', methods=['POST'])
@token_required
def add_device(current_user):
    try:
        data = request.json
        device_id = data.get('device_id')
        device_name = data.get('device_name', 'My Device')
        
        if not device_id:
            return jsonify({'error': 'Device ID is required'}), 400
        
        existing_device = devices_collection.find_one({'device_id': device_id})
        
        if existing_device:
            if existing_device['user_email'] == current_user['email']:
                return jsonify({'error': 'Device already in your account'}), 400
            else:
                return jsonify({
                    'error': 'Device already registered to another account',
                    'owner': existing_device['user_email']
                }), 400
        
        user = users_collection.find_one({'email': current_user['email']})
        if device_id in user.get('devices', []):
            return jsonify({'error': 'Device already in your account'}), 400
        
        user_agent = request.headers.get('User-Agent', 'Unknown')
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
            'last_seen': datetime.datetime.utcnow(),
            'location_tracking': False,
            'current_section': 'Outside Campus'
        }
        
        result = devices_collection.insert_one(device)
        device['_id'] = str(result.inserted_id)
        
        users_collection.update_one(
            {'email': current_user['email']},
            {'$push': {'devices': device_id}}
        )
        
        device_status = {
            'device_id': device_id,
            'device_exists': True,
            'user_has_device': True,
            'device_status': 'registered_to_me',
            'device_owner': current_user['email'],
            'os': os
        }
        
        updated_user = users_collection.find_one({'email': current_user['email']})
        if len(updated_user.get('devices', [])) >= 2:
            start_ml_training(current_user['email'])
        
        return jsonify({
            'message': 'Device added successfully',
            'device': serialize_document(device),
            'device_status': device_status,
            'ml_training_started': len(updated_user.get('devices', [])) >= 2
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
        import traceback
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
            'device_id_fix': 'APPLIED'
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
    print(f"🛡️ DEVICE_ID FIX APPLIED:")
    print(f"   - WebSocket auth includes device_id")
    print(f"   - Multiple fallback sources for device_id")
    print(f"   - Hard validation prevents null device_id")
    print(f"   - Worker crash protection enabled")
    print(f"🔧 MULTI-DEVICE SYSTEM READY")
    
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)