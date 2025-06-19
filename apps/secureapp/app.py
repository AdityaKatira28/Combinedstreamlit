import streamlit as st
import time
from datetime import datetime
from core.base_app import BaseAppInterface
from utils.ui_components import create_metric_card, create_status_badge
from .models import SecureAppModel

class SecureAppInterface(BaseAppInterface):
    def initialize(self):
        # Initialize session state
        if 'secure_model' not in st.session_state:
            try:
                st.session_state.secure_model = SecureAppModel()
            except Exception as e:
                st.error(f"Failed to load SecureApp model: {e}")
                st.session_state.secure_model = None
        
        if 'assessment_history' not in st.session_state:
            st.session_state.assessment_history = []
    
    def render(self):
        st.markdown("## 🔍 Application Risk Assessment")
        
        # Assessment form
        self.render_assessment_form()
        
        # Results dashboard
        if st.session_state.assessment_history:
            st.markdown("---")
            self.render_dashboard()
    
    def render_assessment_form(self):
        with st.form("assessment_form", clear_on_submit=True):
            col1, col2 = st.columns(2)
            
            with col1:
                app_id = st.text_input("Application ID", placeholder="e.g., APP001")
                criticality = st.selectbox("Business Criticality", 
                                         ["low", "medium", "high", "critical"])
                pii_exposure = st.selectbox("PII Exposure", ["No", "Yes"])
            
            with col2:
                exposure = st.selectbox("Network Exposure", ["internal", "external"])
                cvss_score = st.slider("Average CVSS Score", 0.0, 10.0, 5.0, 0.1)
                vuln_count = st.number_input("Vulnerability Count", 
                                           min_value=0, max_value=100, value=3)
                compliance_score = st.slider("Compliance Score (%)", 0, 100, 75)
            
            if st.form_submit_button("🚀 Assess Risk"):
                self.process_assessment(app_id, criticality, pii_exposure, 
                                      exposure, cvss_score, vuln_count, compliance_score)
    
    def process_assessment(self, app_id, criticality, pii_exposure, 
                          exposure, cvss_score, vuln_count, compliance_score):
        if not app_id:
            st.error("Application ID is required!")
            return
        
        if st.session_state.secure_model is None:
            st.error("SecureApp model not available")
            return
        
        app_data = {
            'app_id': app_id,
            'criticality': criticality,
            'pii_exposure': pii_exposure,
            'exposure': exposure,
            'cvss_score': cvss_score,
            'vuln_count': vuln_count,
            'compliance_score': compliance_score
        }
        
        with st.spinner("Analyzing application risk..."):
            time.sleep(0.5)  # Simulate processing
            result = st.session_state.secure_model.predict_risk(app_data)
        
        if 'error' not in result:
            # Store result
            record = {**app_data, **result, 
                     'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            st.session_state.assessment_history.append(record)
            
            # Display results
            self.display_assessment_results(result, vuln_count)
        else:
            st.error(f"Assessment failed: {result.get('error')}")
    
    def display_assessment_results(self, result, vuln_count):
        st.success("Assessment completed!")
        
        # Risk overview
        risk_badge = create_status_badge(result['risk_rating'])
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: white; 
                    border-radius: 8px; margin: 1rem 0;">
            <h3>Risk Assessment Result</h3>
            {risk_badge}
            <div style="font-size: 2em; margin: 0.5rem 0; color: #003087;">
                {result['risk_score']}/100
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        metrics = [
            ("Compliance Score", f"{result['controls_compliance']:.1f}%"),
            ("CIS Compliance", f"{result['cis_compliance']:.1f}%"),
            ("Threat Severity", f"{result['threat_severity']:.2f}"),
            ("Vulnerabilities", str(vuln_count))
        ]
        
        for i, (label, value) in enumerate(metrics):
            with [col1, col2, col3, col4][i]:
                st.markdown(create_metric_card(label, value), unsafe_allow_html=True)
    
    def render_dashboard(self):
        st.markdown("## 📊 Assessment Dashboard")
        
        df_hist = st.session_state.assessment_history
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        metrics = [
            ("Total Assessments", len(df_hist)),
            ("Average Risk Score", f"{sum(r['risk_score'] for r in df_hist)/len(df_hist):.1f}"),
            ("Critical Apps", len([r for r in df_hist if r['risk_rating'] == 'Critical'])),
            ("High Risk Apps", len([r for r in df_hist if r['risk_rating'] == 'High']))
        ]
        
        for i, (label, value) in enumerate(metrics):
            with [col1, col2, col3, col4][i]:
                st.markdown(create_metric_card(label, str(value)), unsafe_allow_html=True)
        
        # Recent assessments table
        st.markdown("### Recent Assessments")
        recent_data = []
        for record in df_hist[-10:]:  # Last 10 assessments
            recent_data.append({
                'App ID': record['app_id'],
                'Risk': record['risk_rating'],
                'Score': record['risk_score'],
                'Criticality': record['criticality'],
                'Exposure': record['exposure'],
                'Timestamp': record['timestamp']
            })
        
        if recent_data:
            st.dataframe(recent_data, use_container_width=True)
    
    def get_metrics(self):
        """Return metrics for dashboard overview"""
        if not st.session_state.assessment_history:
            return {
                'primary_value': '0',
                'primary_label': 'Assessments'
            }
        
        history = st.session_state.assessment_history
        critical_count = len([r for r in history if r['risk_rating'] == 'Critical'])
        
        return {
            'primary_value': str(critical_count),
            'primary_label': 'Critical Apps'
        }