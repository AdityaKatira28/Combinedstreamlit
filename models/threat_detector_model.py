import os
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

class ThreatDetectionModel:
    def __init__(self):
        model_dir = os.path.dirname(__file__)
        pkl_path = os.path.join(model_dir, 'threat_detector_model.pkl')

        if os.path.exists(pkl_path):
            with open(pkl_path, 'rb') as f:
                self.model = pickle.load(f)
        else:
            self.model = RandomForestClassifier(n_estimators=10, random_state=42)
            with open(pkl_path, 'wb') as f:
                pickle.dump(self.model, f)

        self.encoder = LabelEncoder()

    def analyze_logs(self, df: pd.DataFrame) -> dict:
        # Example: feature engineering + predict_proba
        X = self._prepare_features(df)
        scaled = self.encoder.fit_transform(X)
        proba = self.model.predict_proba(scaled.reshape(-1, 1))[:, 1]
        return {
            'total_events': len(df),
            'threats_detected': int((proba > 0.5).sum()),
            'avg_risk': float(proba.mean()),
            'high_risk_events': int((proba > 0.8).sum())
        }

    def _prepare_features(self, df):
        # Stub: use event name length
        return df.index.to_series().map(lambda i: len(str(df.iloc[i])))