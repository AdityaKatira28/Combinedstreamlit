import pickle
import numpy as np
import streamlit as st
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

class SecureAppModel:
    def __init__(self):
        self.classifier = None
        self.scaler = None
        self.feature_names = [
            'cvss_score', 'vuln_count', 'pii_exposure', 
            'criticality', 'exposure', 'compliance_score'
        ]
        self.weights = {}
        self._load_model()
        self._load_metadata()
    
    def _load_metadata(self):
        """Load model metadata"""
        try:
            with open("models/model_metadata.pkl", "rb") as f:
                metadata = pickle.load(f)
            self.feature_names = metadata["feature_names"]
            if "config" in metadata and "client" in metadata["config"] and "weights" in metadata["config"]["client"]:
                self.weights = metadata["config"]["client"]["weights"]
            else:
                st.warning("Client weights not found in model_metadata.pkl. Using default weights.")
                self.weights = {
                    'cvss_weight': 0.30,
                    'vuln_weight': 0.15,
                    'pii_weight': 0.20,
                    'criticality_weight': 0.15,
                    'exposure_weight': 0.10,
                    'compliance_weight': 0.15,
                    'threat_weight': 0.25
                }
        except FileNotFoundError:
            st.error("model_metadata.pkl not found. Please ensure it's in the 'models' directory.")
            st.stop()
        except Exception as e:
            st.error(f"Error loading model metadata: {e}")
            st.stop()
    
    def _load_model(self):
        """Load pre-trained model and scaler"""
        try:
            with open('models/secureapp_model.pkl', 'rb') as f:
                self.classifier = pickle.load(f)
            with open('models/scaler.pkl', 'rb') as f:
                self.scaler = pickle.load(f)
        except FileNotFoundError:
            st.error("Model files not found. Please ensure 'secureapp_model.pkl' and 'scaler.pkl' are in the 'models' directory.")
            st.stop()
        except Exception as e:
            st.error(f"Error loading model files: {e}")
            st.stop()
    
    def predict_risk(self, app_data):
        """Predict risk for an application"""
        if not self.classifier or not self.scaler:
            return {"error": "Model not loaded"}
        
        # Extract base features
        cvss_score = app_data.get('cvss_score', 5.0)
        vuln_count = app_data.get('vuln_count', 3)
        pii_exposure = 1 if app_data.get('pii_exposure') == 'Yes' else 0
        criticality = {'low': 0, 'medium': 0.5, 'high': 1.0, 'critical': 1.5}.get(
            app_data.get('criticality', 'medium'), 0.5
        )
        exposure = 1 if app_data.get('exposure') == 'external' else 0
        compliance_score = app_data.get('compliance_score', 75)
        
        # Calculate derived features to match the 13 features expected by the model
        threat_severity = min(1.0, (cvss_score / 10.0) * (1 + criticality))
        cvss_vuln_interaction = cvss_score * vuln_count / 10.0
        pii_exposure_risk = pii_exposure * (1 + criticality)
        external_pii_risk = exposure * pii_exposure * cvss_score / 10.0
        compliance_risk_ratio = (100 - compliance_score) / 100.0
        threat_vuln_correlation = threat_severity * vuln_count / 10.0
        weighted_risk_score = (
            cvss_score * 0.3 + 
            vuln_count * 0.15 + 
            pii_exposure * 20 * 0.2 + 
            criticality * 25 * 0.15 + 
            exposure * 15 * 0.1 + 
            compliance_risk_ratio * 100 * 0.15
        )
        
        # Prepare all features in the correct order
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
        
        features = np.array([feature_values[name] for name in self.feature_names]).reshape(1, -1)
        
        # Scale features and predict
        features_scaled = self.scaler.transform(features)
        risk_prob = self.classifier.predict_proba(features_scaled)[0][1]
        risk_score = risk_prob * 100
        
        # Determine risk rating
        if risk_score >= 80:
            risk_rating = "Critical"
        elif risk_score >= 60:
            risk_rating = "High"
        elif risk_score >= 40:
            risk_rating = "Medium"
        else:
            risk_rating = "Low"
        
        # Calculate breakdown
        breakdown = {
            'CVSS Score': risk_score * self.weights['cvss_weight'],
            'Exposure': risk_score * self.weights['exposure_weight'],
            'Criticality': risk_score * self.weights['criticality_weight'],
            'Compliance': risk_score * self.weights['compliance_weight'],
            'PII Exposure': risk_score * self.weights['pii_weight']
        }
        
        return {
            'risk_score': round(risk_score, 2),
            'risk_rating': risk_rating,
            'breakdown': breakdown,
            'controls_compliance': app_data.get('compliance_score', 75),
            'cis_compliance': min(85, app_data.get('compliance_score', 75) + 10),
            'threat_severity': risk_prob
        }