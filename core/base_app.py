from abc import ABC, abstractmethod
import streamlit as st

class BaseAppInterface(ABC):
    """Base interface that all apps must implement"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.initialize()
    
    def initialize(self):
        """Initialize app-specific resources"""
        pass
    
    @abstractmethod
    def render(self):
        """Render the app UI"""
        pass
    
    @abstractmethod
    def get_metrics(self):
        """Return app metrics for dashboard overview"""
        pass
    
    def get_sidebar_content(self):
        """Optional sidebar content"""
        return None
