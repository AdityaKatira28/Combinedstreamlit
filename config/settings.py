class DashboardConfig:
    PAGE_TITLE = "Unified Security Dashboard"
    THEME_PRIMARY = "#003087"
    THEME_SECONDARY = "#e3f2fd"
    
    # App Registry - Add new apps here
    REGISTERED_APPS = [
        {
            "name": "Application Risk Assessment",
            "icon": "🔍",
            "module": "apps.secureapp.app",
            "class": "SecureAppInterface"
        },
        {
            "name": "Log Analysis",
            "icon": "📊", 
            "module": "apps.threat_detector.app",
            "class": "ThreatDetectorInterface"
        }
        # Add new apps here easily:
        # {
        #     "name": "Network Scanner",
        #     "icon": "🌐",
        #     "module": "apps.network_scanner.app", 
        #     "class": "NetworkScannerInterface"
        # }
    ]