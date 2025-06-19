import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
import pandas as pd
import re
from datetime import datetime

class SecureAppModel:
    def __init__(self):
        model_dir = os.path.dirname(__file__)
        # Load metadata if exists
        metadata_path = os.path.join(model_dir, 'model_metadata.pkl')
        try:
            with open(metadata_path, 'rb') as f:
                metadata = pickle.load(f)
            self.feature_names = metadata.get("feature_names", [])
            self.weights = metadata.get("config", {}).get("client", {}).get("weights", {})
        except:
            # defaults
            self.feature_names = ['cvss_score','vuln_count','pii_exposure','criticality','exposure','compliance_score','threat_severity','cvss_vuln_interaction','pii_exposure_risk','external_pii_risk','compliance_risk_ratio','threat_vuln_correlation','weighted_risk_score']
            self.weights = {
                'cvss_weight': 0.30,
                'vuln_weight': 0.15,
                'pii_weight': 0.20,
                'criticality_weight': 0.15,
                'exposure_weight': 0.10,
                'compliance_weight': 0.15,
                'threat_weight': 0.25
            }
        # Load classifier & scaler
        try:
            with open(os.path.join(model_dir, 'secureapp_model.pkl'), 'rb') as f:
                self.classifier = pickle.load(f)
        except:
            self.classifier = RandomForestClassifier(n_estimators=10, random_state=42)
            # Optionally save
            with open(os.path.join(model_dir, 'secureapp_model.pkl'), 'wb') as f:
                pickle.dump(self.classifier, f)
        try:
            with open(os.path.join(model_dir, 'scaler.pkl'), 'rb') as f:
                self.scaler = pickle.load(f)
        except:
            self.scaler = StandardScaler()

    def predict_risk(self, app_data: dict) -> dict:
        # Mirror monolithic computations
        try:
            cvss_score = app_data.get('cvss_score', 5.0)
            vuln_count = app_data.get('vuln_count', 3)
            pii_exposure = 1 if app_data.get('pii_exposure') == 'Yes' else 0
            criticality_map = {'low':0, 'medium':0.5, 'high':1.0, 'critical':1.5}
            criticality = criticality_map.get(app_data.get('criticality', 'medium'), 0.5)
            exposure = 1 if app_data.get('exposure') == 'external' else 0
            compliance_score = app_data.get('compliance_score', 75)
            threat_severity = min(1.0, (cvss_score/10.0)*(1+criticality))
            cvss_vuln_interaction = cvss_score * vuln_count / 10.0
            pii_exposure_risk = pii_exposure * (1 + criticality)
            external_pii_risk = exposure * pii_exposure * cvss_score / 10.0
            compliance_risk_ratio = (100 - compliance_score)/100.0
            threat_vuln_correlation = threat_severity * vuln_count / 10.0
            weighted_risk_score = (cvss_score * 0.3 + vuln_count * 0.15 + pii_exposure * 20 * 0.2 + criticality * 25 * 0.15 + exposure * 15 * 0.1 + compliance_risk_ratio * 100 * 0.15)
            feature_values = {
                'cvss_score': cvss_score,
                'vuln_count': vuln_count,
                'pii_exposure': pii_exposure,
                'criticality': criticality,
                'exposure': exposure,
                'compliance_score': compliance_score,
                'threat_severity': threat_severity,
                'cvss_vuln_interaction': cvss_vuln_interaction,
                'pii_exposure_risk': pii_exposure_risk,
                'external_pii_risk': external_pii_risk,
                'compliance_risk_ratio': compliance_risk_ratio,
                'threat_vuln_correlation': threat_vuln_correlation,
                'weighted_risk_score': weighted_risk_score
            }
            # Build feature vector in correct order
            features = np.array([feature_values[name] for name in self.feature_names]).reshape(1, -1)
            # Scale & predict
            try:
                features_scaled = self.scaler.transform(features)
                risk_prob = self.classifier.predict_proba(features_scaled)[0][1]
            except Exception:
                # fallback: simple weighted combination normalized
                risk_prob = weighted_risk_score / 100.0
            risk_score = risk_prob * 100
            if risk_score >= 80:
                risk_rating = "Critical"
            elif risk_score >= 60:
                risk_rating = "High"
            elif risk_score >= 40:
                risk_rating = "Medium"
            else:
                risk_rating = "Low"
            breakdown = {
                'CVSS Score': risk_score * self.weights.get('cvss_weight',0.3),
                'Exposure': risk_score * self.weights.get('exposure_weight',0.1),
                'Criticality': risk_score * self.weights.get('criticality_weight',0.15),
                'Compliance': risk_score * self.weights.get('compliance_weight',0.15),
                'PII Exposure': risk_score * self.weights.get('pii_weight',0.2)
            }
            return {
                'risk_score': round(risk_score, 2),
                'risk_rating': risk_rating,
                'breakdown': breakdown,
                'controls_compliance': compliance_score,
                'cis_compliance': min(85, compliance_score + 10),
                'threat_severity': risk_prob
            }
        except Exception as e:
            return {'error': f"Error in predict_risk: {e}"}
