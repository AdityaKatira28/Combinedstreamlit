import streamlit as st
from shared_config import set_page_config, apply_global_css, initialize_session_state
from risk_assessment_module import render_risk_assessment
from log_analysis_module import render_log_analysis

def main():
    """Main application function"""
    # Set page configuration
    set_page_config()
    
    # Apply global CSS
    apply_global_css()
    
    # Initialize session state
    initialize_session_state()
    
    # Main header
    st.markdown('<div class="main-header"><h1>Unified Dashboard</h1></div>', unsafe_allow_html=True)
    
    # Create main tabs
    tab1, tab2 = st.tabs(["Application Risk Assessment", "Log Analysis"])
    
    with tab1:
        render_risk_assessment()
    
    with tab2:
        render_log_analysis()

if __name__ == "__main__":
    main()