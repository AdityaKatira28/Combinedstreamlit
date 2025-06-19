import pkgutil
import importlib
import streamlit as st
from abc import ABC, abstractmethod

class BaseAppInterface(ABC):
    def __init__(self):
        self.initialize()

    def initialize(self):
        pass

    @abstractmethod
    def render(self):
        pass

    @abstractmethod
    def get_metrics(self):
        pass

class DashboardManager:
    def __init__(self):
        self.apps = {}
        self._load_apps()

    def _load_apps(self):
        # auto-discover any apps/*.py
        for finder, name, ispkg in pkgutil.iter_modules(['apps']):
            try:
                mod = importlib.import_module(f"apps.{name}")
                app_cls = getattr(mod, 'Interface', None)
                if app_cls and issubclass(app_cls, BaseAppInterface):
                    self.apps[mod.APP_NAME] = {
                        'instance': app_cls(),
                        'icon': mod.ICON
                    }
            except Exception as e:
                st.error(f"Failed loading app {name}: {e}")

    def render(self):
        st.markdown(
            """
            <div style="text-align:center; padding:2rem; background:#003087; color:white; border-radius:10px;">
              <h1>🛡️ Unified Security Dashboard</h1>
            </div>
            """, unsafe_allow_html=True)
        self._render_overview()
        tabs = st.tabs([f"{v['icon']} {k}" for k,v in self.apps.items()])
        for tab, (name, data) in zip(tabs, self.apps.items()):
            with tab:
                data['instance'].render()

    def _render_overview(self):
        st.markdown("## 📈 Overview")
        cols = st.columns(len(self.apps) or 1)
        for col, (name, data) in zip(cols, self.apps.items()):
            with col:
                m = data['instance'].get_metrics()
                st.markdown(
                    f"**{data['icon']} {name}**  
                     **{m['primary_value']}**  
                     _{m['primary_label']}_"
                )