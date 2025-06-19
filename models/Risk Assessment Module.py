import streamlit as st
import pandas as pd
import plotly.express as px
import time
from datetime import datetime
from shared_config import apply_global_css

def render_risk_assessment():
    """Render the risk assessment interface"""
    # Apply CSS specifically for this module
    apply_global_css()
    
    st.markdown("## 🔍 Application Risk Assessment")
    
    with st.form("assessment_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        
        with col1:
            app_id = st.text_input("Application ID", placeholder="e.g., APP001")
            criticality = st.selectbox("Business Criticality", ["low", "medium", "high", "critical"])
            pii_exposure = st.selectbox("PII Exposure", ["No", "Yes"])
        
        with col2:
            exposure = st.selectbox("Network Exposure", ["internal", "external"])
            cvss_score = st.slider("Average CVSS Score", 0.0, 10.0, 5.0, 0.1)
            vuln_count = st.number_input("Vulnerability Count", min_value=0, max_value=100, value=3)
        
        compliance_score = st.slider("Compliance Score (%)", 0, 100, 75)
        submit = st.form_submit_button("🚀 Assess Risk")
        
        if submit:
            if not app_id:
                st.error("Application ID is required!")
            else:
                if st.session_state.secure_model is None:
                    st.error("SecureApp model not initialized.")
                else:
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
                        time.sleep(0.5)
                        result = st.session_state.secure_model.predict_risk(app_data)
                    
                    if 'error' not in result:
                        record = {
                            **app_data, 
                            **result, 
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        st.session_state.assessment_history.append(record)
                        
                        st.success(f"Assessment completed for {app_id}")
                        
                        # Display results
                        risk_class = f"risk-{result['risk_rating'].lower()}"
                        st.markdown(f'<div class="material-card {risk_class}"><h3>Risk: {result["risk_rating"]} ({result["risk_score"]}/100)</h3></div>', unsafe_allow_html=True)
                        
                        # Metrics
                        met1, met2, met3, met4 = st.columns(4)
                        met1.metric("Compliance Score", f"{result['controls_compliance']:.1f}%")
                        met2.metric("CIS Compliance", f"{result['cis_compliance']:.1f}%")
                        met3.metric("Threat Severity", f"{result['threat_severity']:.2f}")
                        met4.metric("Vulnerabilities", vuln_count)
                        
                        # Breakdown chart
                        st.markdown("### Risk Factor Breakdown")
                        df_break = pd.DataFrame([{"Factor": k, "Contribution": v} for k, v in result['breakdown'].items()])
                        fig = px.bar(df_break, x="Factor", y="Contribution", title="Risk Breakdown", 
                                   color="Contribution", color_continuous_scale="RdYlBu_r")
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Recommendations
                        render_recommendations(result['risk_rating'])
                    else:
                        st.error(f"Assessment failed: {result.get('error')}")
    
    # Dashboard
    render_assessment_dashboard()

def render_recommendations(risk_rating):
    """Render recommendations based on risk rating"""
    st.markdown("### Recommendations")
    if risk_rating == 'Critical':
        st.error("🚨 Immediate action required!")
        st.markdown("- Implement controls immediately\n- Conduct thorough review")
    elif risk_rating == 'High':
        st.warning("⚠️ High priority")
        st.markdown("- Schedule assessment\n- Review policies")
    elif risk_rating == 'Medium':
        st.info("Monitor closely")
        st.markdown("- Regular monitoring\n- Quarterly review")
    else:
        st.success("Good posture")
        st.markdown("- Continue practices\n- Annual review")

def render_assessment_dashboard():
    """Render the assessment dashboard"""
    st.markdown("---")
    st.markdown("## 📊 Assessment Dashboard")
    
    if st.session_state.assessment_history:
        df_hist = pd.DataFrame(st.session_state.assessment_history)
        
        # Metrics
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Assessments", len(df_hist))
        c2.metric("Average Risk Score", f"{df_hist['risk_score'].mean():.1f}")
        c3.metric("Critical Applications", len(df_hist[df_hist['risk_rating'] == 'Critical']))
        c4.metric("High Risk Applications", len(df_hist[df_hist['risk_rating'] == 'High']))
        
        # Charts
        col1, col2 = st.columns(2)
        with col1:
            counts = df_hist['risk_rating'].value_counts()
            fig_pie = px.pie(values=counts.values, names=counts.index, title="Risk Distribution")
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            scores = pd.to_numeric(df_hist['risk_score'], errors='coerce').dropna()
            if not scores.empty:
                fig_hist = px.histogram(x=scores, nbins=20, title="Risk Score Distribution")
                st.plotly_chart(fig_hist, use_container_width=True)
        
        st.markdown("### Recent Assessments")
        st.dataframe(df_hist[['app_id', 'risk_rating', 'risk_score', 'criticality', 'exposure', 'timestamp']].tail(10), 
                    use_container_width=True)
    else:
        st.info("No assessments yet.")