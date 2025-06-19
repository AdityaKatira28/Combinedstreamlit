import streamlit as st
import pandas as pd
from core import BaseAppInterface
from models.secureapp_model import SecureAppModel
from datetime import datetime
import numpy as np
import time
import plotly.express as px

APP_NAME = "Application Risk Assessment"
ICON = "🔍"

class Interface(BaseAppInterface):
    def initialize(self):
        # Initialize the SecureAppModel once per session
        if 'secure_model' not in st.session_state:
            st.session_state.secure_model = SecureAppModel()
        # History of assessments
        if 'assessment_history' not in st.session_state:
            st.session_state.assessment_history = []

    def render(self):
        st.markdown("## 🔍 Application Risk Assessment")
        with st.form("assessment_form", clear_on_submit=True):
            col1, col2 = st.columns(2)
            with col1:
                app_id = st.text_input("Application ID", placeholder="e.g., APP001")
                criticality = st.selectbox("Business Criticality", ["low","medium","high","critical"])
                pii_exposure = st.selectbox("PII Exposure", ["No","Yes"])
            with col2:
                exposure = st.selectbox("Network Exposure", ["internal","external"])
                cvss_score = st.slider("Average CVSS Score", 0.0, 10.0, 5.0, 0.1)
                vuln_count = st.number_input("Vulnerability Count", min_value=0, max_value=100, value=3)
                compliance_score = st.slider("Compliance Score (%)", 0, 100, 75)
            submit = st.form_submit_button("🚀 Assess Risk")

        if submit:
            if not app_id:
                st.error("Application ID is required!")
            else:
                model = st.session_state.secure_model
                # Prepare dict matching the monolithic logic
                app_data = {
                    'cvss_score': cvss_score,
                    'vuln_count': vuln_count,
                    'pii_exposure': pii_exposure,
                    'criticality': criticality,
                    'exposure': exposure,
                    'compliance_score': compliance_score
                }
                with st.spinner("Analyzing application risk..."):
                    result = model.predict_risk(app_data)
                if 'error' not in result:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    record = {
                        'app_id': app_id,
                        'criticality': criticality,
                        'pii_exposure': pii_exposure,
                        'exposure': exposure,
                        'cvss_score': cvss_score,
                        'vuln_count': vuln_count,
                        'compliance_score': compliance_score,
                        **result,
                        'timestamp': timestamp
                    }
                    st.session_state.assessment_history.append(record)
                    st.success(f"Assessment completed for {app_id}")
                    # Display result summary
                    st.markdown(f"### Risk: {result['risk_rating']} ({result['risk_score']}/100)")
                    met1,met2,met3,met4 = st.columns(4)
                    met1.metric("Compliance Score", f"{result['controls_compliance']:.1f}%")
                    met2.metric("CIS Compliance", f"{result['cis_compliance']:.1f}%")
                    met3.metric("Threat Severity", f"{result['threat_severity']:.2f}")
                    met4.metric("Vulnerabilities", vuln_count)
                    # Breakdown chart
                    if 'breakdown' in result and isinstance(result['breakdown'], dict):
                        df_break = pd.DataFrame([{"Factor":k,"Contribution":v} for k,v in result['breakdown'].items()])
                        fig = px.bar(df_break, x="Factor", y="Contribution", title="Risk Breakdown", color="Contribution", color_continuous_scale="RdYlBu_r")
                        st.plotly_chart(fig, use_container_width=True)
                    # Recommendations similar to monolithic
                    if result['risk_rating']=='Critical':
                        st.error("🚨 Immediate action required!")
                        st.markdown("- Implement controls immediately\n- Conduct thorough review")
                    elif result['risk_rating']=='High':
                        st.warning("⚠️ High priority")
                        st.markdown("- Schedule assessment\n- Review policies")
                    elif result['risk_rating']=='Medium':
                        st.info("Monitor closely")
                        st.markdown("- Regular monitoring\n- Quarterly review")
                    else:
                        st.success("Good posture")
                        st.markdown("- Continue practices\n- Annual review")
                else:
                    st.error(f"Assessment failed: {result.get('error')}")
        # Dashboard of history
        history = st.session_state.assessment_history
        if history:
            st.markdown("---")
            st.markdown("## 📊 Assessment Dashboard")
            df = pd.DataFrame(history)
            c1,c2,c3,c4 = st.columns(4)
            c1.metric("Total Assessments", len(df))
            c2.metric("Average Risk Score", f"{df['risk_score'].mean():.1f}")
            c3.metric("Critical Applications", len(df[df['risk_rating']=='Critical']))
            c4.metric("High Risk Applications", len(df[df['risk_rating']=='High']))
            # Further distribution charts can be added as needed
        else:
            st.info("No assessments yet.")
