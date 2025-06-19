import streamlit as st
import pandas as pd
from core import BaseAppInterface
from models.threat_detector_model import ThreatDetectionModel

APP_NAME = "Log Analysis"
ICON = "📊"

class Interface(BaseAppInterface):
    def initialize(self):
        if 'threat_model' not in st.session_state:
            st.session_state.threat_model = ThreatDetectionModel()

    def render(self):
        st.markdown("## 📊 AI Threat Detection")
        uploaded = st.file_uploader("Upload CloudTrail Logs", type=['csv','json'])
        if uploaded:
            df = pd.read_csv(uploaded) if uploaded.name.endswith('.csv') else pd.read_json(uploaded)
            results = st.session_state.threat_model.analyze_logs(df)
            st.json(results)

    def get_metrics(self):
        return { 'primary_value': '0', 'primary_label': 'Analyses' }