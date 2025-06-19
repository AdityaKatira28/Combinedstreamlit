import streamlit as st
import pandas as pd
import numpy as np
from core.base_app import BaseAppInterface
from utils.ui_components import create_metric_card
from .models import ThreatDetectionModel

class ThreatDetectorInterface(BaseAppInterface):
    def initialize(self):
        if 'threat_model' not in st.session_state:
            st.session_state.threat_model = ThreatDetectionModel()
        
        if 'analysis_results' not in st.session_state:
            st.session_state.analysis_results = []
    
    def render(self):
        st.markdown("## 📊 AI Threat Detection")
        
        # File upload
        uploaded_file = st.file_uploader(
            "Upload CloudTrail Logs", 
            type=['json', 'csv'],
            help="Upload CloudTrail logs in JSON or CSV format"
        )
        
        if uploaded_file:
            self.process_uploaded_file(uploaded_file)
        
        # Sample data generation
        if st.button("🎲 Generate Sample Data"):
            self.generate_sample_analysis()
    
    def process_uploaded_file(self, uploaded_file):
        try:
            # Load data
            if uploaded_file.name.endswith('.json'):
                df = pd.read_json(uploaded_file)
            else:
                df = pd.read_csv(uploaded_file)
            
            st.success(f"Loaded {len(df)} records from {uploaded_file.name}")
            
            # Process with threat detection
            with st.spinner("Analyzing threats..."):
                results = st.session_state.threat_model.analyze_logs(df)
            
            self.display_analysis_results(results)
            
        except Exception as e:
            st.error(f"Error processing file: {e}")
    
    def generate_sample_analysis(self):
        with st.spinner("Generating sample data and analysis..."):
            # Generate synthetic data
            sample_data = st.session_state.threat_model.generate_sample_data(1000)
            results = st.session_state.threat_model.analyze_logs(sample_data)
        
        self.display_analysis_results(results)
    
    def display_analysis_results(self, results):
        # Store results
        st.session_state.analysis_results.append(results)
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        metrics = [
            ("Total Events", results['total_events']),
            ("Threats Detected", results['threats_detected']),
            ("Risk Score", f"{results['avg_risk']:.1%}"),
            ("High Risk Events", results['high_risk_events'])
        ]
        
        for i, (label, value) in enumerate(metrics):
            with [col1, col2, col3, col4][i]:
                st.markdown(create_metric_card(label, str(value)), unsafe_allow_html=True)
        
        # Results table
        st.markdown("### Analysis Results")
        if 'detailed_results' in results:
            st.dataframe(results['detailed_results'], use_container_width=True)
    
    def get_metrics(self):
        """Return metrics for dashboard overview"""
        if not st.session_state.analysis_results:
            return {
                'primary_value': '0',
                'primary_label': 'Analyses'
            }
        
        latest = st.session_state.analysis_results[-1]
        
        return {
            'primary_value': str(latest['threats_detected']),
            'primary_label': 'Threats Found'
        }