import pickle
import numpy as np
import pandas as pd
import streamlit as st

class SecureAppModel:
    def __init__(self):
        self.classifier = None
        self.scaler = None
        self.feature_names = []
        self.weights = {}
        self._load_model()
        self._load_metadata()
    
    def _load_metadata(self):
        try:
            with open("models/model_metadata.pkl", "rb") as f:
                metadata = pickle.load(f)
            self.feature_names = metadata.get("feature_names", self.feature_names)
            config = metadata.get("config", {})
            client_cfg = config.get("client", {})
            self.weights = client_cfg.get("weights", {
                'cvss_weight': 0.30,
                'vuln_weight': 0.15,
                'pii_weight': 0.20,
                'criticality_weight': 0.15,
                'exposure_weight': 0.10,
                'compliance_weight': 0.15,
                'threat_weight': 0.25
            })
        except FileNotFoundError:
            st.warning("SecureApp metadata not found; using defaults.")
            if not self.feature_names:
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
        except Exception as e:
            st.error(f"Error loading SecureApp metadata: {e}")
            raise e
    
    def _load_model(self):
        try:
            with open('models/secureapp_model.pkl', 'rb') as f:
                self.classifier = pickle.load(f)
            with open('models/scaler.pkl', 'rb') as f:
                self.scaler = pickle.load(f)
        except FileNotFoundError:
            st.error("SecureApp model files not found in 'models' directory.")
            raise FileNotFoundError("Model files not found")
        except Exception as e:
            st.error(f"Error loading SecureApp model: {e}")
            raise e
    
    def predict_risk(self, app_data):
        """Predict risk for application data"""
        if not self.classifier or not self.scaler:
            return {"error": "SecureApp model not loaded"}
        
        # Extract features
        cvss_score = app_data.get('cvss_score', 5.0)
        vuln_count = app_data.get('vuln_count', 3)
        pii_exposure = 1 if app_data.get('pii_exposure') == 'Yes' else 0
        criticality = {'low': 0, 'medium': 0.5, 'high': 1.0, 'critical': 1.5}.get(app_data.get('criticality', 'medium'), 0.5)
        exposure = 1 if app_data.get('exposure') == 'external' else 0
        compliance_score = app_data.get('compliance_score', 75)
        
        # Calculate derived features
        threat_severity = min(1.0, (cvss_score / 10.0) * (1 + criticality))
        cvss_vuln_interaction = cvss_score * vuln_count / 10.0
        pii_exposure_risk = pii_exposure * (1 + criticality)
        external_pii_risk = exposure * pii_exposure * cvss_score / 10.0
        compliance_risk_ratio = (100 - compliance_score) / 100.0
        threat_vuln_correlation = threat_severity * vuln_count / 10.0
        weighted_risk_score = (cvss_score * 0.3 + vuln_count * 0.15 + pii_exposure * 20 * 0.2 + 
                              criticality * 25 * 0.15 + exposure * 15 * 0.1 + compliance_risk_ratio * 100 * 0.15)
        
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
        
        try:
            features = np.array([feature_values[name] for name in self.feature_names]).reshape(1, -1)
            features_scaled = self.scaler.transform(features)
            risk_prob = self.classifier.predict_proba(features_scaled)[0][1]
        except Exception:
            # Fallback: simple weighted combination
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
            'CVSS Score': risk_score * self.weights.get('cvss_weight', 0.3),
            'Exposure': risk_score * self.weights.get('exposure_weight', 0.1),
            'Criticality': risk_score * self.weights.get('criticality_weight', 0.15),
            'Compliance': risk_score * self.weights.get('compliance_weight', 0.15),
            'PII Exposure': risk_score * self.weights.get('pii_weight', 0.2)
        }
        
        return {
            'risk_score': round(risk_score, 2),
            'risk_rating': risk_rating,
            'breakdown': breakdown,
            'controls_compliance': compliance_score,
            'cis_compliance': min(85, compliance_score + 10),
            'threat_severity': risk_prob
        }