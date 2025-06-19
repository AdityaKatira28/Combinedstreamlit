import streamlit as st

def apply_global_styles():
    st.markdown(
        """
        <style>
        .stApp { background: #f0f4ff; }
        .metric-card { padding:1rem; border-radius:8px; background: white; box-shadow:0 1px 3px rgba(0,0,0,0.1); margin-bottom:1rem; }
        </style>
        """, unsafe_allow_html=True)
