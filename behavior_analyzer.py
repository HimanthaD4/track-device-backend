import math
from datetime import datetime, timedelta
import pymongo
import numpy as np
from collections import defaultdict

class BehaviorAnalyzer:
    def __init__(self, db):
        self.db = db
        self.behavior_collection = db.device_behaviors
        self.training_status_collection = db.training_status
        self.device_patterns_collection = db.device_patterns
        
        # Create indexes
        try:
            self.behavior_collection.create_index([('user_email', 1), ('timestamp', 1)])
            self.training_status_collection.create_index([('user_email', 1)], unique=True)
            self.device_patterns_collection.create_index([('user_email', 1), ('device_id', 1)])
        except Exception as e:
            print(f"Index creation warning: {e}")
    
    def get_section_id(self, section_name):
        """Convert section name to numeric ID"""
        section_map = {
            'Main Building': 1,
            'Library': 2,
            'New Building': 3,
            'Canteen': 4,
            'Sports Complex': 5,
            'Admin Block': 6,
            'Outside Campus': 0
        }
        return section_map.get(section_name, 0)
    
    def calculate_distance(self, lat1, lon1, lat2, lon2):
        """Calculate distance between two points in meters"""
        R = 6371000
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)
        
        a = math.sin(delta_phi/2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        
        return R * c
    
    def calculate_movement_speed(self, device_id, current_lat, current_lon, current_time):
        """Calculate device movement speed"""
        last_location = self.behavior_collection.find_one(
            {'device_id': device_id},
            sort=[('timestamp', -1)]
        )
        
        if not last_location:
            return 0
        
        time_diff = (current_time - last_location['timestamp']).total_seconds()
        if time_diff == 0:
            return 0
        
        distance = self.calculate_distance(
            last_location['latitude'],
            last_location['longitude'],
            current_lat,
            current_lon
        )
        
        speed = distance / time_diff  # meters per second
        return speed
    
    def analyze_device_pair(self, user_email, device1_data, device2_data):
        """Analyze behavior between two devices"""
        current_time = datetime.utcnow()
        
        # Calculate distance between devices
        distance = self.calculate_distance(
            device1_data['latitude'],
            device1_data['longitude'],
            device2_data['latitude'],
            device2_data['longitude']
        )
        
        # Get section IDs
        device1_section_id = self.get_section_id(device1_data.get('current_section', 'Outside Campus'))
        device2_section_id = self.get_section_id(device2_data.get('current_section', 'Outside Campus'))
        
        # Check if both inside campus
        both_inside = device1_section_id > 0 and device2_section_id > 0
        
        # Calculate movement speeds
        speed1 = self.calculate_movement_speed(
            device1_data['device_id'],
            device1_data['latitude'],
            device1_data['longitude'],
            current_time
        )
        
        speed2 = self.calculate_movement_speed(
            device2_data['device_id'],
            device2_data['latitude'],
            device2_data['longitude'],
            current_time
        )
        
        # Time of day and day of week
        time_of_day = current_time.hour
        day_of_week = current_time.weekday()  # Monday=0, Sunday=6
        
        # Calculate if devices are moving together
        moving_together = 1 if (speed1 > 0.5 and speed2 > 0.5 and distance < 50) else 0
        
        # Calculate section difference
        section_diff = abs(device1_section_id - device2_section_id)
        
        # Create behavior record
        behavior_record = {
            'user_email': user_email,
            'device1_id': device1_data['device_id'],
            'device2_id': device2_data['device_id'],
            'distance_between_devices': distance,
            'device1_section_id': device1_section_id,
            'device2_section_id': device2_section_id,
            'both_inside_campus': 1 if both_inside else 0,
            'movement_speed_device1': speed1,
            'movement_speed_device2': speed2,
            'time_of_day': time_of_day,
            'day_of_week': day_of_week,
            'same_section': 1 if device1_section_id == device2_section_id else 0,
            'device1_outside': 1 if device1_section_id == 0 else 0,
            'device2_outside': 1 if device2_section_id == 0 else 0,
            'moving_together': moving_together,
            'section_difference': section_diff,
            'timestamp': current_time,
            'device1_lat': device1_data['latitude'],
            'device1_lon': device1_data['longitude'],
            'device2_lat': device2_data['latitude'],
            'device2_lon': device2_data['longitude']
        }
        
        # Store behavior record
        self.behavior_collection.insert_one(behavior_record)
        
        # Update individual device patterns
        self.update_device_pattern(user_email, device1_data['device_id'], {
            'section_id': device1_section_id,
            'speed': speed1,
            'timestamp': current_time,
            'latitude': device1_data['latitude'],
            'longitude': device1_data['longitude'],
            'with_other_device': device2_data['device_id'],
            'distance_to_other': distance
        })
        
        self.update_device_pattern(user_email, device2_data['device_id'], {
            'section_id': device2_section_id,
            'speed': speed2,
            'timestamp': current_time,
            'latitude': device2_data['latitude'],
            'longitude': device2_data['longitude'],
            'with_other_device': device1_data['device_id'],
            'distance_to_other': distance
        })
        
        return behavior_record
    
    def update_device_pattern(self, user_email, device_id, data):
        """Update individual device behavior patterns"""
        # Get existing pattern or create new
        pattern = self.device_patterns_collection.find_one({
            'user_email': user_email,
            'device_id': device_id
        })
        
        if not pattern:
            pattern = {
                'user_email': user_email,
                'device_id': device_id,
                'section_visits': defaultdict(int),
                'typical_sections': [],
                'movement_patterns': [],
                'companion_devices': [],
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
        
        # Update section visits
        section_id = data['section_id']
        pattern['section_visits'][str(section_id)] += 1
        
        # Update companion devices
        if 'with_other_device' in data:
            if data['with_other_device'] not in pattern['companion_devices']:
                pattern['companion_devices'].append(data['with_other_device'])
        
        # Update movement patterns
        movement_entry = {
            'speed': data['speed'],
            'timestamp': data['timestamp'],
            'section_id': section_id
        }
        pattern['movement_patterns'].append(movement_entry)
        
        # Keep only last 100 movement patterns
        if len(pattern['movement_patterns']) > 100:
            pattern['movement_patterns'] = pattern['movement_patterns'][-100:]
        
        # Update timestamp
        pattern['updated_at'] = datetime.utcnow()
        
        # Calculate typical sections (most visited)
        if len(pattern['section_visits']) > 0:
            typical = sorted(pattern['section_visits'].items(), key=lambda x: x[1], reverse=True)[:3]
            pattern['typical_sections'] = [int(s[0]) for s in typical if int(s[0]) > 0]
        
        # Save/update pattern
        self.device_patterns_collection.update_one(
            {'user_email': user_email, 'device_id': device_id},
            {'$set': pattern},
            upsert=True
        )
    
    def get_device_pattern(self, user_email, device_id):
        """Get behavior pattern for specific device"""
        return self.device_patterns_collection.find_one({
            'user_email': user_email,
            'device_id': device_id
        })
    
    def get_training_data(self, user_email, limit=500):
        """Get all behavior data for training"""
        behavior_data = list(self.behavior_collection.find(
            {'user_email': user_email},
            {'_id': 0}
        ).sort('timestamp', -1).limit(limit))
        
        # Return in chronological order
        behavior_data.reverse()
        return behavior_data
    
    def get_training_status(self, user_email):
        """Get training status for user"""
        status = self.training_status_collection.find_one({'user_email': user_email})
        return status
    
    def update_training_status(self, user_email, status_data):
        """Update training status"""
        self.training_status_collection.update_one(
            {'user_email': user_email},
            {'$set': status_data},
            upsert=True
        )
    
    def get_recent_behavior_summary(self, user_email, minutes=10):
        """Get summary of recent device behavior"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        
        pipeline = [
            {'$match': {
                'user_email': user_email,
                'timestamp': {'$gte': cutoff_time}
            }},
            {'$group': {
                '_id': {
                    'device1': '$device1_id',
                    'device2': '$device2_id'
                },
                'avg_distance': {'$avg': '$distance_between_devices'},
                'same_section_count': {'$sum': '$same_section'},
                'moving_together_count': {'$sum': '$moving_together'},
                'total_samples': {'$sum': 1}
            }}
        ]
        
        results = list(self.behavior_collection.aggregate(pipeline))
        return results