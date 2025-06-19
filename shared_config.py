import streamlit as st
import warnings

# Suppress warnings globally
warnings.filterwarnings('ignore')

def apply_global_css():
    """Apply global CSS styling that works across all modules"""
    css = '''
    <style>
        /* Shared Material Design-like styling */
        :root {
            --primary-100: #e3f2fd;
            --primary-500: #003087;
            --primary-900: #001a4d;
            --surface-primary-10: rgba(0, 48, 135, 0.04);
            --surface-primary-20: rgba(0, 48, 135, 0.08);
            --surface-primary-30: rgba(0, 48, 135, 0.12);
            --background-primary: #f0f4ff;
            --surface-container: #ffffff;
            --surface-container-low: #f8faff;
        }
        
        /* Global body styling */
        .stApp {
            font-family: 'Arial', sans-serif;
            color: #262730;
            background-color: var(--background-primary);
        }
        
        /* Main header styling */
        .main-header { 
            text-align: center; 
            padding: 1rem 0; 
            margin-bottom: 1rem; 
            color: white; 
            background: linear-gradient(135deg, var(--primary-500), var(--primary-900)); 
            border-radius: 8px; 
        }
        
        /* Section headers */
        .section-header { 
            color: var(--primary-500); 
            font-size: 1.8rem; 
            font-weight: 700; 
            margin-bottom: 1rem; 
            padding-bottom: 0.5rem; 
            border-bottom: 2px solid var(--primary-500); 
        }
        
        /* Material cards */
        .material-card { 
            background-color: var(--surface-container); 
            border-radius: 12px; 
            padding: 15px; 
            box-shadow: 0 4px 8px rgba(0,0,0,0.05); 
            margin-bottom: 15px; 
            border: 1px solid var(--primary-100); 
            transition: all 0.3s ease; 
        }
        
        .material-card:hover { 
            transform: translateY(-3px); 
            box-shadow: 0 8px 16px var(--surface-primary-20); 
            background-color: var(--surface-container-low); 
            border-color: var(--primary-500); 
        }
        
        /* Metric styling */
        .material-metric-value { 
            font-size: 2em; 
            font-weight: 700; 
            color: var(--primary-500); 
            margin-top: 5px; 
        }
        
        .material-metric-label { 
            font-size: 0.9em; 
            color: #6C757D; 
            text-transform: uppercase; 
            letter-spacing: 0.5px; 
        }
        
        /* Button styling */
        .stButton > button { 
            background-color: var(--primary-500); 
            color: white; 
            border-radius: 50px; 
            padding: 10px 20px; 
            font-size: 14px; 
            border: 2px solid transparent; 
            transition: all 0.3s ease; 
            font-weight: 600; 
        }
        
        .stButton > button:hover { 
            background-color: var(--primary-900); 
            transform: scale(1.05); 
            box-shadow: 0 4px 12px var(--surface-primary-30); 
        }
        
        /* Chart container */
        .chart-container { 
            background-color: var(--surface-container); 
            border-radius: 12px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.03); 
            padding: 20px; 
            margin-bottom: 15px; 
            border: 1px solid var(--primary-100); 
            transition: all 0.3s ease; 
        }
        
        .chart-container:hover { 
            box-shadow: 0 4px 8px var(--surface-primary-20); 
            background-color: var(--surface-container-low); 
        }
        
        /* Risk level specific styling */
        .risk-critical { border-left: 5px solid #dc3545; }
        .risk-high { border-left: 5px solid #fd7e14; }
        .risk-medium { border-left: 5px solid #ffc107; }
        .risk-low { border-left: 5px solid #28a745; }
        
        .threat-critical { border-left: 5px solid #dc3545; }
        .threat-high { border-left: 5px solid #fd7e14; }
        .threat-medium { border-left: 5px solid #ffc107; }
        .threat-low { border-left: 5px solid #28a745; }
        
        /* Hide Streamlit branding */
        #MainMenu {visibility: hidden;} 
        footer {visibility: hidden;} 
        header {visibility: hidden;}
        
        /* Ensure consistent spacing */
        .element-container { margin-bottom: 1rem; }
        
        /* Tab styling */
        .stTabs [data-baseweb="tab-list"] {
            gap: 2px;
        }
        
        .stTabs [data-baseweb="tab"] {
            height: 50px;
            padding-left: 20px;
            padding-right: 20px;
            background-color: var(--surface-container);
            border-radius: 8px 8px 0 0;
            border: 1px solid var(--primary-100);
        }
        
        .stTabs [aria-selected="true"] {
            background-color: var(--primary-500);
            color: white;
        }
    </style>
    '''
    st.markdown(css, unsafe_allow_html=True)

def set_page_config():
    """Set page configuration for the app"""
    st.set_page_config(
        page_title="Unified Dashboard - SecureApp & AI Log Analysis",
        layout="wide",
        initial_sidebar_state="collapsed"
    )

def initialize_session_state():
    """Initialize session state variables"""
    if 'assessment_history' not in st.session_state:
        st.session_state.assessment_history = []
    
    if 'secure_model' not in st.session_state:
        try:
            from secure_app_model import SecureAppModel
            st.session_state.secure_model = SecureAppModel()
        except Exception as e:
            st.error(f"Failed to load SecureApp model: {e}")
            st.session_state.secure_model = None