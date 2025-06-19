import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

class SecureAppModel:
    def __init__(self):
        # Determine absolute path to .pkl
        model_dir = os.path.dirname(__file__)
        pkl_path = os.path.join(model_dir, 'secureapp_model.pkl')

        # Load or initialize classifier
        if os.path.exists(pkl_path):
            with open(pkl_path, 'rb') as f:
                self.classifier = pickle.load(f)
        else:
            self.classifier = RandomForestClassifier(n_estimators=10, random_state=42)
            # Optionally: train or save a fresh model
            with open(pkl_path, 'wb') as f:
                pickle.dump(self.classifier, f)

        # Scaler
        self.scaler = StandardScaler()

    def predict_risk(self, features: np.ndarray) -> float:
        # Ensure features is 2D
        feats = features.reshape(1, -1)
        scaled = self.scaler.fit_transform(feats)
        # Assume classifier supports predict_proba
        prob = self.classifier.predict_proba(scaled)[0][1]
        return prob