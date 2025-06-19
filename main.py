import streamlit as st
from config.settings import DashboardConfig
from core.dashboard import DashboardManager
from utils.ui_components import apply_global_styles

def main():
    # Page configuration
    st.set_page_config(
        page_title=DashboardConfig.PAGE_TITLE,
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    # Apply global styles
    apply_global_styles()
    
    # Initialize dashboard
    dashboard = DashboardManager()
    
    # Render dashboard
    dashboard.render()

if __name__ == "__main__":
    main()