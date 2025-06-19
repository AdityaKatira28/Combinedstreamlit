import streamlit as st
import numpy as np
from core import BaseAppInterface
from models.secureapp_model import SecureAppModel

APP_NAME = "Application Risk Assessment"
ICON = "🔍"

class Interface(BaseAppInterface):
    def initialize(self):
        if 'secure_model' not in st.session_state:
            st.session_state.secure_model = SecureAppModel()

    def render(self):
        st.markdown("## 🔍 Application Risk Assessment")
        cvss = st.slider("CVSS Score", 0.0, 10.0, 5.0)
        if st.button("Assess Risk"):
            score = st.session_state.secure_model.predict_risk(np.array([cvss]))
            st.success(f"Risk Probability: {score:.2%}")

    def get_metrics(self):
        # Example metric: dummy count
        return { 'primary_value': '0', 'primary_label': 'Assessments' }