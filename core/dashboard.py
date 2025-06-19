import importlib
import streamlit as st
from config.settings import DashboardConfig
from core.base_app import BaseAppInterface

class DashboardManager:
    def __init__(self):
        self.apps = {}
        self.load_apps()
    
    def load_apps(self):
        """Dynamically load all registered apps"""
        for app_config in DashboardConfig.REGISTERED_APPS:
            try:
                module = importlib.import_module(app_config["module"])
                app_class = getattr(module, app_config["class"])
                
                # Verify it implements BaseAppInterface
                if issubclass(app_class, BaseAppInterface):
                    self.apps[app_config["name"]] = {
                        "instance": app_class(),
                        "icon": app_config["icon"],
                        "config": app_config
                    }
                else:
                    st.warning(f"App {app_config['name']} doesn't implement BaseAppInterface")
                    
            except Exception as e:
                st.error(f"Failed to load app {app_config['name']}: {e}")
    
    def render(self):
        """Render the main dashboard"""
        # Header
        st.markdown("""
        <div style="text-align: center; padding: 2rem 0; margin-bottom: 2rem; 
                    background: linear-gradient(135deg, #003087, #001a4d); 
                    border-radius: 12px; color: white;">
            <h1>🛡️ Unified Security Dashboard</h1>
            <p>Centralized security analysis and monitoring</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Overview metrics
        self.render_overview()
        
        # App tabs
        tab_names = [f"{app['icon']} {name}" for name, app in self.apps.items()]
        tabs = st.tabs(tab_names)
        
        for i, (app_name, app_data) in enumerate(self.apps.items()):
            with tabs[i]:
                try:
                    app_data["instance"].render()
                except Exception as e:
                    st.error(f"Error rendering {app_name}: {e}")
    
    def render_overview(self):
        """Render dashboard overview with metrics from all apps"""
        st.markdown("## 📈 Dashboard Overview")
        
        cols = st.columns(len(self.apps))
        
        for i, (app_name, app_data) in enumerate(self.apps.items()):
            with cols[i]:
                try:
                    metrics = app_data["instance"].get_metrics()
                    st.markdown(f"""
                    <div style="background: white; padding: 1rem; border-radius: 8px; 
                                box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center;">
                        <h4>{app_data['icon']} {app_name}</h4>
                        <div style="font-size: 1.5em; color: #003087; font-weight: bold;">
                            {metrics.get('primary_value', 'N/A')}
                        </div>
                        <div style="color: #666; font-size: 0.9em;">
                            {metrics.get('primary_label', 'Status')}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                except Exception as e:
                    st.error(f"Error getting metrics for {app_name}")
