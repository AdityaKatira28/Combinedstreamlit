import streamlit as st

def apply_global_styles():
    """Apply global CSS styles"""
    st.markdown("""
    <style>
    :root {
        --primary-500: #003087;
        --primary-900: #001a4d;
        --surface-container: #ffffff;
        --background-primary: #f0f4ff;
    }
    
    .stApp {
        background-color: var(--background-primary);
    }
    
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        border-left: 4px solid var(--primary-500);
        margin-bottom: 1rem;
    }
    
    .risk-critical { border-left-color: #dc3545; }
    .risk-high { border-left-color: #fd7e14; }
    .risk-medium { border-left-color: #ffc107; }
    .risk-low { border-left-color: #28a745; }
    
    .stButton > button {
        background: linear-gradient(135deg, var(--primary-500), var(--primary-900));
        color: white;
        border: none;
        border-radius: 25px;
        padding: 0.5rem 2rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,48,135,0.3);
    }
    </style>
    """, unsafe_allow_html=True)

def create_metric_card(title, value, subtitle=None, risk_level=None):
    """Create a styled metric card"""
    risk_class = f"risk-{risk_level.lower()}" if risk_level else ""
    subtitle_html = f"<small style='color: #666;'>{subtitle}</small>" if subtitle else ""
    
    return f"""
    <div class="metric-card {risk_class}">
        <h4 style="margin: 0 0 0.5rem 0; color: var(--primary-500);">{title}</h4>
        <div style="font-size: 2em; font-weight: bold; margin: 0.5rem 0;">{value}</div>
        {subtitle_html}
    </div>
    """

def create_status_badge(status, color_map=None):
    """Create a status badge"""
    if color_map is None:
        color_map = {
            "critical": "#dc3545",
            "high": "#fd7e14", 
            "medium": "#ffc107",
            "low": "#28a745"
        }
    
    color = color_map.get(status.lower(), "#6c757d")
    
    return f"""
    <span style="background: {color}; color: white; padding: 0.25rem 0.75rem; 
                 border-radius: 15px; font-size: 0.8em; font-weight: bold;">
        {status.upper()}
    </span>