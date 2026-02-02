import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import pickle
import os
from datetime import datetime, timedelta
import json
import joblib

class DeviceBehaviorModel:
    def __init__(self, user_email):
        self.user_email = user_email
        self.model = None
        self.scaler = StandardScaler()
        self.kmeans = None
        self.is_trained = False
        self.training_start_time = None
        self.training_duration_minutes = 5  # 5 minutes for demo
        self.min_training_samples = 30  # Minimum samples needed for training
        self.normal_patterns = {}
        self.anomaly_threshold = -0.5  # Lower = more sensitive
        
    def extract_features(self, behavior_data):
        """Extract enhanced features from device behavior data"""
        features = []
        
        for record in behavior_data:
            # Enhanced feature vector
            feature_vector = [
                record.get('distance_between_devices', 0),
                record.get('device1_section_id', 0),
                record.get('device2_section_id', 0),
                record.get('both_inside_campus', 0),
                record.get('movement_speed_device1', 0),
                record.get('movement_speed_device2', 0),
                record.get('time_of_day', 0),
                record.get('day_of_week', 0) if 'day_of_week' in record else 0,
                record.get('same_section', 0),
                record.get('device1_outside', 0),
                record.get('device2_outside', 0),
                record.get('moving_together', 0) if 'moving_together' in record else 0,
                record.get('section_difference', 0) if 'section_difference' in record else 0,
                # Additional derived features
                abs(record.get('movement_speed_device1', 0) - record.get('movement_speed_device2', 0)),
                1 if record.get('device1_section_id', 0) == 0 and record.get('device2_section_id', 0) > 0 else 0,
                1 if record.get('device1_section_id', 0) > 0 and record.get('device2_section_id', 0) == 0 else 0,
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def extract_individual_features(self, device_data, companion_data=None):
        """Extract features for individual device analysis"""
        features = []
        
        # Device alone features
        alone_features = [
            device_data.get('section_id', 0),
            device_data.get('speed', 0),
            1 if device_data.get('section_id', 0) == 0 else 0,  # Outside campus
            device_data.get('time_of_day', 0) if 'time_of_day' in device_data else 0,
        ]
        
        # With companion features
        if companion_data:
            companion_features = [
                companion_data.get('distance_to_other', 0),
                1 if companion_data.get('with_other_device') else 0,
                1 if device_data.get('section_id', 0) == companion_data.get('section_id', 0) else 0,
            ]
            features = alone_features + companion_features
        else:
            # Pad with zeros if no companion
            features = alone_features + [0, 0, 0]
        
        return np.array([features])
    
    def train_model(self, behavior_data, device_patterns=None):
        """Train the anomaly detection model with enhanced features"""
        if len(behavior_data) < self.min_training_samples:
            print(f"⚠️ Need at least {self.min_training_samples} samples, got {len(behavior_data)}")
            return False, f"Need at least {self.min_training_samples} samples, got {len(behavior_data)}"
        
        print(f"🤖 Training ML model with {len(behavior_data)} samples...")
        
        # Extract enhanced features
        features = self.extract_features(behavior_data)
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Train Isolation Forest with adjusted parameters
        self.model = IsolationForest(
            contamination=0.15,  # Expect 15% anomalies (more sensitive for demo)
            random_state=42,
            n_estimators=150,
            max_samples='auto',
            bootstrap=True
        )
        self.model.fit(features_scaled)
        
        # Train KMeans for pattern clustering
        self.kmeans = KMeans(n_clusters=3, random_state=42)
        cluster_labels = self.kmeans.fit_predict(features_scaled)
        
        # Store normal patterns (cluster centroids)
        self.normal_patterns = {
            'cluster_centers': self.kmeans.cluster_centers_.tolist(),
            'cluster_sizes': np.bincount(cluster_labels).tolist(),
            'feature_means': np.mean(features_scaled, axis=0).tolist(),
            'feature_stds': np.std(features_scaled, axis=0).tolist()
        }
        
        # Calculate anomaly scores for training data
        train_scores = self.model.score_samples(features_scaled)
        self.anomaly_threshold = np.percentile(train_scores, 10)  # Bottom 10% as potential anomalies
        
        self.is_trained = True
        print(f"✅ ML Model trained successfully. Anomaly threshold: {self.anomaly_threshold:.3f}")
        return True, "Model trained successfully"
    
    def predict_anomaly(self, current_behavior):
        """Predict if current behavior is anomaly with confidence"""
        if not self.is_trained:
            return False, 0.0, "Model not trained yet", {}
        
        features = self.extract_features([current_behavior])
        
        if features.shape[0] == 0:
            return False, 0.0, "No features extracted", {}
        
        features_scaled = self.scaler.transform(features)
        
        # Get anomaly score (lower = more abnormal)
        score = self.model.score_samples(features_scaled)[0]
        
        # Get cluster distance
        if self.kmeans:
            cluster_distances = self.kmeans.transform(features_scaled)
            min_cluster_distance = np.min(cluster_distances)
            assigned_cluster = np.argmin(cluster_distances)
        else:
            min_cluster_distance = 0
            assigned_cluster = -1
        
        # Calculate confidence
        confidence = abs(score)
        
        # Determine if anomaly (score below threshold)
        is_anomaly = score < self.anomaly_threshold
        
        # Get feature importance for explanation
        anomaly_details = {
            'score': float(score),
            'threshold': float(self.anomaly_threshold),
            'cluster_distance': float(min_cluster_distance),
            'assigned_cluster': int(assigned_cluster),
            'is_anomaly': bool(is_anomaly),
            'confidence': float(confidence),
            'features': {
                'distance': float(current_behavior.get('distance_between_devices', 0)),
                'device1_section': int(current_behavior.get('device1_section_id', 0)),
                'device2_section': int(current_behavior.get('device2_section_id', 0)),
                'same_section': bool(current_behavior.get('same_section', 0)),
                'moving_together': bool(current_behavior.get('moving_together', 0) if 'moving_together' in current_behavior else 0),
                'device1_outside': bool(current_behavior.get('device1_outside', 0)),
                'device2_outside': bool(current_behavior.get('device2_outside', 0))
            }
        }
        
        return is_anomaly, confidence, "Prediction successful", anomaly_details
    
    def detect_individual_anomaly(self, device_data, companion_data=None):
        """Detect anomalies in individual device behavior"""
        if not self.is_trained:
            return False, 0.0, {}, "Model not trained yet"
        
        features = self.extract_individual_features(device_data, companion_data)
        
        # Use the same scaler (may need separate scaler for individual features)
        # For now, use simple rule-based detection
        
        anomaly_reasons = []
        
        # Rule 1: Device moved too fast (> 5 m/s ≈ 18 km/h)
        if device_data.get('speed', 0) > 5.0:
            anomaly_reasons.append(f"High speed: {device_data.get('speed', 0):.1f} m/s")
        
        # Rule 2: Device outside campus when companion is inside
        if companion_data:
            if device_data.get('section_id', 0) == 0 and companion_data.get('section_id', 0) > 0:
                anomaly_reasons.append("Device left campus while companion stayed")
            elif device_data.get('section_id', 0) > 0 and companion_data.get('section_id', 0) == 0:
                anomaly_reasons.append("Companion left campus while device stayed")
        
        # Rule 3: Unusual section for this time (simplified)
        time_of_day = datetime.utcnow().hour
        if time_of_day > 18 and device_data.get('section_id', 0) in [1, 2]:  # Evening in Library/Main Building
            anomaly_reasons.append("Unusual location for evening hours")
        
        is_anomaly = len(anomaly_reasons) > 0
        
        anomaly_details = {
            'is_anomaly': is_anomaly,
            'reasons': anomaly_reasons,
            'confidence': min(0.7 + (len(anomaly_reasons) * 0.1), 0.95),
            'device_data': device_data,
            'companion_data': companion_data
        }
        
        return is_anomaly, anomaly_details
    
    def save_model(self, filepath):
        """Save trained model to disk"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'kmeans': self.kmeans,
            'is_trained': self.is_trained,
            'training_start_time': self.training_start_time,
            'anomaly_threshold': self.anomaly_threshold,
            'normal_patterns': self.normal_patterns,
            'user_email': self.user_email
        }
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"💾 Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load trained model from disk"""
        if os.path.exists(filepath):
            try:
                with open(filepath, 'rb') as f:
                    model_data = pickle.load(f)
                    self.model = model_data['model']
                    self.scaler = model_data['scaler']
                    self.kmeans = model_data.get('kmeans')
                    self.is_trained = model_data['is_trained']
                    self.training_start_time = model_data['training_start_time']
                    self.anomaly_threshold = model_data.get('anomaly_threshold', -0.5)
                    self.normal_patterns = model_data.get('normal_patterns', {})
                print(f"📂 Model loaded from {filepath}")
                return True
            except Exception as e:
                print(f"❌ Error loading model: {e}")
                return False
        return False
    
    def get_model_info(self):
        """Get information about the trained model"""
        if not self.is_trained:
            return {"status": "Not trained"}
        
        info = {
            "status": "Trained",
            "training_start_time": self.training_start_time.isoformat() if self.training_start_time else None,
            "anomaly_threshold": self.anomaly_threshold,
            "normal_patterns_count": len(self.normal_patterns.get('cluster_centers', [])),
            "model_type": "Isolation Forest + KMeans"
        }
        
        return info