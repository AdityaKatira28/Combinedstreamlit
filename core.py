import pkgutil
import importlib
import streamlit as st
from abc import ABC, abstractmethod

class BaseAppInterface(ABC):
    def __init__(self):
        # Called once per session initialization
        self.initialize()

    def initialize(self):
        # Override to set up session_state or other initialization
        pass

    @abstractmethod
    def render(self):
        # Override to render Streamlit UI for this app
        pass

    def get_metrics(self):
        # Default metrics; override in apps if desired
        return {'primary_value': '0', 'primary_label': ''}

class DashboardManager:
    def __init__(self):
        self.apps = {}
        self._load_apps()

    def _load_apps(self):
        # Auto-discover any .py modules under apps/ directory
        for finder, name, ispkg in pkgutil.iter_modules(['apps']):
            try:
                mod = importlib.import_module(f"apps.{name}")
                app_cls = getattr(mod, 'Interface', None)
                if app_cls and issubclass(app_cls, BaseAppInterface):
                    app_name = getattr(mod, 'APP_NAME', name)
                    icon = getattr(mod, 'ICON', '')
                    # Instantiate interface (calls initialize)
                    instance = app_cls()
                    self.apps[app_name] = {'instance': instance, 'icon': icon}
            except Exception as e:
                st.error(f"Error loading app '{name}': {e}")

    def render(self):
        if self.apps:
            # Create tabs for each app
            tabs = st.tabs([f"{v['icon']} {name}" for name, v in self.apps.items()])
            for tab, (name, data) in zip(tabs, self.apps.items()):
                with tab:
                    data['instance'].render()
        else:
            st.info("No apps found to display.")
