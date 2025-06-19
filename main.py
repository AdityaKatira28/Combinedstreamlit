import streamlit as st
from core import DashboardManager
from utils import apply_global_styles

def main():
    st.set_page_config(
        page_title="Unified Security Dashboard",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    apply_global_styles()
    DashboardManager().render()

if __name__ == "__main__":
    main()