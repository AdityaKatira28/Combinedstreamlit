import pandas as pd
import numpy as np
import re
import json
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import streamlit as st

class ThreatDetectionModel:
    def __init__(self):
        self.model = None
        self.encoders = {}
        self.feature_columns = []
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize or load the threat detection model"""
        try:
            # Try to load existing model (implement your loading logic here)
            # For now, create a mock model
            self._create_mock_model()
        except Exception as e:
            st.warning(f"Creating mock threat detection model: {e}")
            self._create_mock_model()
    
    def _create_mock_model(self):
        """Create a mock model for demonstration"""
        # Define feature columns
        self.feature_columns = [
            'hour', 'day_of_week', 'is_weekend', 'is_night',
            'is_private_ip', 'ip_first_octet', 'user_agent_length',
            'is_boto3', 'is_console', 'is_cli', 'has_error',
            'is_access_denied', 'is_create_event', 'is_delete_event',
            'is_list_event', 'is_admin_event', 'is_sensitive_api',
            'eventName_encoded', 'eventSource_encoded', 'awsRegion_encoded'
        ]
        
        # Create mock model
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        
        # Create mock training data
        X_mock = np.random.rand(100, len(self.feature_columns))
        y_mock = np.random.randint(0, 2, 100)
        self.model.fit(X_mock, y_mock)
        
        # Create mock encoders
        self.encoders = {
            'eventName': LabelEncoder().fit(['CreateUser', 'AssumeRole', 'DeleteUser']),
            'eventSource': LabelEncoder().fit(['iam.amazonaws.com', 's3.amazonaws.com']),
            'awsRegion': LabelEncoder().fit(['us-east-1', 'us-west-2'])
        }
    
    def analyze_logs(self, df):
        """Analyze logs and return threat assessment"""
        try:
            # Extract features
            df_features = self._extract_features(df)
            
            # Select features in correct order
            X = df_features[self.feature_columns]
            
            # Predict threats
            probs = self.model.predict_proba(X)[:, 1]
            preds = self.model.predict(X)
            
            # Return results
            return {
                'total_events': len(df),
                'threats_detected': int(sum(preds)),
                'avg_risk': float(np.mean(probs)),
                'high_risk_events': int(sum(probs >= 0.6)),
                'detailed_results': pd.DataFrame({
                    'event': df_features.index,
                    'risk_score': probs,
                    'threat': preds
                })
            }
        except Exception as e:
            st.error(f"Analysis error: {e}")
            return {
                'total_events': 0,
                'threats_detected': 0,
                'avg_risk': 0,
                'high_risk_events': 0
            }
    
    def _extract_features(self, df):
        """Extract features from log data"""
        df_feat = df.copy()
        
        # Convert eventTime to datetime if it's a string
        if 'eventTime' in df_feat.columns:
            df_feat['eventTime'] = pd.to_datetime(df_feat['eventTime'], errors='coerce')
            # Extract time-based features
            df_feat['hour'] = df_feat['eventTime'].dt.hour
            df_feat['day_of_week'] = df_feat['eventTime'].dt.dayofweek
            df_feat['is_weekend'] = df_feat['day_of_week'].isin([5, 6]).astype(int)
            df_feat['is_night'] = ((df_feat['hour'] >= 22) | (df_feat['hour'] <= 6)).astype(int)
        else:
            # Default values if eventTime is missing
            df_feat['hour'] = 12
            df_feat['day_of_week'] = 1
            df_feat['is_weekend'] = 0
            df_feat['is_night'] = 0
        
        # IP-based features
        if 'sourceIPAddress' in df_feat.columns:
            # Check if IP is private
            def is_private_ip(ip):
                if pd.isna(ip) or not isinstance(ip, str):
                    return 0
                private_patterns = [
                    r'^10\.',
                    r'^192\.168\.',
                    r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'
                ]
                return int(any(re.match(pattern, ip) for pattern in private_patterns))
            
            df_feat['is_private_ip'] = df_feat['sourceIPAddress'].apply(is_private_ip)
            
            # Extract IP octets
            def get_first_octet(ip):
                if pd.isna(ip) or not isinstance(ip, str):
                    return 0
                try:
                    return int(ip.split('.')[0])
                except:
                    return 0
            
            df_feat['ip_first_octet'] = df_feat['sourceIPAddress'].apply(get_first_octet)
        else:
            df_feat['is_private_ip'] = 0
            df_feat['ip_first_octet'] = 0
        
        # User Agent features
        if 'userAgent' in df_feat.columns:
            df_feat['user_agent_length'] = df_feat['userAgent'].fillna('').astype(str).str.len()
            df_feat['is_boto3'] = df_feat['userAgent'].fillna('').str.contains('boto3', case=False).astype(int)
            df_feat['is_console'] = df_feat['userAgent'].fillna('').str.contains('console', case=False).astype(int)
            df_feat['is_cli'] = df_feat['userAgent'].fillna('').str.contains('aws-cli', case=False).astype(int)
        else:
            df_feat['user_agent_length'] = 0
            df_feat['is_boto3'] = 0
            df_feat['is_console'] = 0
            df_feat['is_cli'] = 0
        
        # Event name features
        if 'eventName' in df_feat.columns:
            df_feat['is_create_event'] = df_feat['eventName'].fillna('').str.contains('Create', case=False).astype(int)
            df_feat['is_delete_event'] = df_feat['eventName'].fillna('').str.contains('Delete', case=False).astype(int)
            df_feat['is_list_event'] = df_feat['eventName'].fillna('').str.contains('List|Describe', case=False).astype(int)
            df_feat['is_admin_event'] = df_feat['eventName'].fillna('').str.contains('Admin|Root|Policy', case=False).astype(int)
            df_feat['is_sensitive_api'] = df_feat['eventName'].fillna('').apply(lambda x: x in ['CreateUser', 'AttachUserPolicy', 'CreateRole', 'AssumeRole']).astype(int)
            
            # Encode categorical features
            if 'eventName' in self.encoders:
                df_feat['eventName_encoded'] = df_feat['eventName'].apply(
                    lambda x: self.encoders['eventName'].transform([x])[0] if x in self.encoders['eventName'].classes_ else -1
                )
            else:
                df_feat['eventName_encoded'] = 0
        else:
            df_feat['is_create_event'] = 0
            df_feat['is_delete_event'] = 0
            df_feat['is_list_event'] = 0
            df_feat['is_admin_event'] = 0
            df_feat['is_sensitive_api'] = 0
            df_feat['eventName_encoded'] = 0
        
        # Fill any remaining NaN values
        df_feat = df_feat.fillna(0)
        return df_feat
    
    def generate_sample_data(self, num_events=1000):
        """Generate synthetic CloudTrail data for demonstration"""
        # Implementation similar to the original App1's generate_synthetic_cloudtrail_data
        # (Omitted for brevity - can be copied from the original implementation)
        return pd.DataFrame(np.random.rand(num_events, len(self.feature_columns)))