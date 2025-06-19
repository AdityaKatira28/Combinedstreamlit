import os
import pickle
import numpy as np
import pandas as pd
import re
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

class ThreatDetectionModel:
    def __init__(self):
        model_dir = os.path.dirname(__file__)
        # Try load model
        try:
            with open(os.path.join(model_dir, 'aws_threat_detection_model.pkl'), 'rb') as f:
                self.model = pickle.load(f)
            # If you saved feature_columns & encoders, load them too
            with open(os.path.join(model_dir, 'feature_columns.pkl'), 'rb') as f:
                self.feature_columns = pickle.load(f)
            with open(os.path.join(model_dir, 'encoders.pkl'), 'rb') as f:
                self.encoders = pickle.load(f)
        except:
            # Mock model
            self.feature_columns = ['hour','day_of_week','is_weekend','is_night','is_private_ip','ip_first_octet','user_agent_length','is_boto3','is_console','is_cli','has_error','is_access_denied','is_create_event','is_delete_event','is_list_event','is_admin_event','is_external_ip','is_sensitive_api','suspicious_user_agent','eventName_encoded','eventSource_encoded','awsRegion_encoded']
            self.encoders = {
                'eventName': LabelEncoder(),
                'eventSource': LabelEncoder(),
                'awsRegion': LabelEncoder()
            }
            # Fit encoders with known classes (as in monolithic)
            self.encoders['eventName'].fit(['AssumeRole','GetSessionToken','CreateUser','DeleteUser','ListUsers','RunInstances','StopInstances','StartInstances','TerminateInstances','DescribeInstances','CreateBucket','DeleteBucket','PutObject','GetObject','ListBuckets'])
            self.encoders['eventSource'].fit(['iam.amazonaws.com','sts.amazonaws.com','s3.amazonaws.com','ec2.amazonaws.com','cloudtrail.amazonaws.com'])
            self.encoders['awsRegion'].fit(['us-east-1','us-east-2','us-west-1','us-west-2','eu-west-1'])
            # Train a mock RandomForest
            self.model = RandomForestClassifier(n_estimators=10, random_state=42)
            X_mock = np.random.rand(100, len(self.feature_columns))
            y_mock = np.random.randint(0,2,100)
            self.model.fit(X_mock, y_mock)

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        df_feat = df.copy()
        # Replicate exactly your monolithic extract_features:
        if 'eventTime' in df_feat.columns:
            df_feat['eventTime'] = pd.to_datetime(df_feat['eventTime'], errors='coerce')
            df_feat['hour'] = df_feat['eventTime'].dt.hour
            df_feat['day_of_week'] = df_feat['eventTime'].dt.dayofweek
            df_feat['is_weekend'] = df_feat['day_of_week'].isin([5,6]).astype(int)
            df_feat['is_night'] = ((df_feat['hour'] >=22)|(df_feat['hour']<=6)).astype(int)
        else:
            df_feat['hour']=12; df_feat['day_of_week']=1; df_feat['is_weekend']=0; df_feat['is_night']=0
        # IP features
        if 'sourceIPAddress' in df_feat.columns:
            def is_private_ip(ip):
                if pd.isna(ip) or not isinstance(ip,str): return 0
                private_patterns=[r'^10\\.',r'^192\\.168\\.',r'^172\\.(1[6-9]|2[0-9]|3[0-1])\\.']
                return int(any(re.match(p,ip) for p in private_patterns))
            df_feat['is_private_ip'] = df_feat['sourceIPAddress'].apply(is_private_ip)
            df_feat['is_external_ip'] = (~df_feat['sourceIPAddress'].apply(lambda x: is_private_ip(x)==1)).astype(int)
            def get_first_octet(ip):
                if pd.isna(ip) or not isinstance(ip,str): return 0
                try: return int(ip.split('.')[0])
                except: return 0
            df_feat['ip_first_octet'] = df_feat['sourceIPAddress'].apply(get_first_octet)
        else:
            df_feat['is_private_ip']=0; df_feat['is_external_ip']=0; df_feat['ip_first_octet']=0
        # userAgent
        if 'userAgent' in df_feat.columns:
            df_feat['user_agent_length'] = df_feat['userAgent'].fillna('').astype(str).str.len()
            df_feat['is_boto3'] = df_feat['userAgent'].fillna('').str.contains('boto3',case=False).astype(int)
            df_feat['is_console'] = df_feat['userAgent'].fillna('').str.contains('console',case=False).astype(int)
            df_feat['is_cli'] = df_feat['userAgent'].fillna('').str.contains('aws-cli',case=False).astype(int)
            suspicious_patterns=['nmap','nessus','metasploit','sqlmap','python','curl','wget']
            df_feat['suspicious_user_agent'] = df_feat['userAgent'].fillna('').apply(lambda x: any(p in x.lower() for p in suspicious_patterns)).astype(int)
        else:
            df_feat['user_agent_length']=0; df_feat['is_boto3']=0; df_feat['is_console']=0; df_feat['is_cli']=0; df_feat['suspicious_user_agent']=0
        # errorCode
        if 'errorCode' in df_feat.columns:
            df_feat['has_error'] = df_feat['errorCode'].notna().astype(int)
            df_feat['is_access_denied'] = df_feat['errorCode'].fillna('').str.contains('AccessDenied',case=False).astype(int)
        else:
            df_feat['has_error']=0; df_feat['is_access_denied']=0
        # eventName
        if 'eventName' in df_feat.columns:
            df_feat['is_create_event'] = df_feat['eventName'].fillna('').str.contains('Create',case=False).astype(int)
            df_feat['is_delete_event'] = df_feat['eventName'].fillna('').str.contains('Delete',case=False).astype(int)
            df_feat['is_list_event'] = df_feat['eventName'].fillna('').str.contains('List|Describe',case=False).astype(int)
            df_feat['is_admin_event'] = df_feat['eventName'].fillna('').str.contains('Admin|Root|Policy',case=False).astype(int)
            sensitive_apis=['CreateUser','AttachUserPolicy','CreateRole','AssumeRole','GetSessionToken','PutBucketPolicy','ModifyDBInstance','RunInstances','AuthorizeSecurityGroupIngress','CreateSnapshot']
            df_feat['is_sensitive_api'] = df_feat['eventName'].fillna('').apply(lambda x: x in sensitive_apis).astype(int)
            # encoding
            if 'eventName' in self.encoders:
                df_feat['eventName_encoded'] = df_feat['eventName'].apply(lambda x: self.encoders['eventName'].transform([x])[0] if x in self.encoders['eventName'].classes_ else -1)
            else:
                df_feat['eventName_encoded'] = 0
        else:
            df_feat['is_create_event']=0; df_feat['is_delete_event']=0; df_feat['is_list_event']=0; df_feat['is_admin_event']=0; df_feat['is_sensitive_api']=0; df_feat['eventName_encoded']=0
        # eventSource
        if 'eventSource' in df_feat.columns and 'eventSource' in self.encoders:
            df_feat['eventSource_encoded'] = df_feat['eventSource'].apply(lambda x: self.encoders['eventSource'].transform([x])[0] if x in self.encoders['eventSource'].classes_ else -1)
        else:
            df_feat['eventSource_encoded']=0
        # awsRegion
        if 'awsRegion' in df_feat.columns and 'awsRegion' in self.encoders:
            df_feat['awsRegion_encoded'] = df_feat['awsRegion'].apply(lambda x: self.encoders['awsRegion'].transform([x])[0] if x in self.encoders['awsRegion'].classes_ else -1)
        else:
            df_feat['awsRegion_encoded']=0
        df_feat = df_feat.fillna(0)
        return df_feat

    def predict_df(self, df: pd.DataFrame):
        try:
            df_feat = self.extract_features(df, )
            # Ensure feature_columns exist
            X = df_feat[self.feature_columns] if all(col in df_feat.columns for col in self.feature_columns) else df_feat.select_dtypes(include=[np.number]).fillna(0)
            if X.isnull().any().any():
                X = X.fillna(0)
            if hasattr(self.model, 'predict_proba'):
                probs = self.model.predict_proba(X)[:,1]
            else:
                probs = self.model.predict(X)
            preds = (probs >= 0.5).astype(int) if hasattr(self.model, 'predict_proba') else self.model.predict(X)
            return preds, probs
        except Exception as e:
            # On error, return zeros
            return np.zeros(len(df), dtype=int), np.zeros(len(df), dtype=float)
