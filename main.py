import streamlit as st
from core import DashboardManager

def main():
    st.set_page_config(
        page_title="Unified Security Dashboard",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    # Import utils here so path resolution works when main.py is run
    from utils import apply_global_styles
    apply_global_styles()
    DashboardManager().render()

if __name__ == "__main__":
    main()
