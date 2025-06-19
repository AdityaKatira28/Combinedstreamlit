import os
import sys
import streamlit as st
import pandas as pd
import numpy as np
import pickle
import io
import time
from datetime import datetime, timedelta
import re
import json
import warnings
import plotly.express as px
import plotly.graph_objects as go
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Suppress warnings
warnings.filterwarnings('ignore')

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Unified Dashboard - SecureApp & AI Log Analysis",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- GLOBAL CSS ---
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
    body { font-family: 'Arial', sans-serif; color: #262730; background-color: var(--background-primary); }
    .main-header { text-align: center; padding: 1rem 0; margin-bottom: 1rem; color: white; background: linear-gradient(135deg, var(--primary-500), var(--primary-900)); border-radius: 8px; }
    .section-header { color: var(--primary-500); font-size: 1.8rem; font-weight: 700; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--primary-500); }
    .material-card { background-color: var(--surface-container); border-radius: 12px; padding: 15px; box-shadow: 0 4px 8px rgba(0,0,0,0.05); margin-bottom: 15px; border: 1px solid var(--primary-100); transition: all 0.3s ease; }
    .material-card:hover { transform: translateY(-3px); box-shadow: 0 8px 16px var(--surface-primary-20); background-color: var(--surface-container-low); border-color: var(--primary-500); }
    .material-metric-value { font-size: 2em; font-weight: 700; color: var(--primary-500); margin-top: 5px; }
    .material-metric-label { font-size: 0.9em; color: #6C757D; text-transform: uppercase; letter-spacing: 0.5px; }
    .stButton > button { background-color: var(--primary-500); color: white; border-radius: 50px; padding: 10px 20px; font-size: 14px; border: 2px solid transparent; transition: all 0.3s ease; font-weight: 600; }
    .stButton > button:hover { background-color: var(--primary-900); transform: scale(1.05); box-shadow: 0 4px 12px var(--surface-primary-30); }
    .chart-container { background-color: var(--surface-container); border-radius: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.03); padding: 20px; margin-bottom: 15px; border: 1px solid var(--primary-100); transition: all 0.3s ease; }
    .chart-container:hover { box-shadow: 0 4px 8px var(--surface-primary-20); background-color: var(--surface-container-low); }
    #MainMenu {visibility: hidden;} footer {visibility: hidden;} header {visibility: hidden;}
</style>
'''
st.markdown(css, unsafe_allow_html=True)

# --- SECUREAPP AI: Application Risk Assessment ---
class SecureAppModel:
    def __init__(self):
        self.classifier = None
        self.scaler = None
        self.feature_names = []
        self.weights = {}
        self._load_model()
        self._load_metadata()
    def _load_metadata(self):
        try:
            with open("models/model_metadata.pkl", "rb") as f:
                metadata = pickle.load(f)
            self.feature_names = metadata.get("feature_names", self.feature_names)
            config = metadata.get("config", {})
            client_cfg = config.get("client", {})
            self.weights = client_cfg.get("weights", {
                'cvss_weight': 0.30,
                'vuln_weight': 0.15,
                'pii_weight': 0.20,
                'criticality_weight': 0.15,
                'exposure_weight': 0.10,
                'compliance_weight': 0.15,
                'threat_weight': 0.25
            })
        except FileNotFoundError:
            st.warning("SecureApp metadata not found; using defaults.")
            # Default feature names if unknown
            if not self.feature_names:
                self.feature_names = ['cvss_score','vuln_count','pii_exposure','criticality','exposure','compliance_score','threat_severity','cvss_vuln_interaction','pii_exposure_risk','external_pii_risk','compliance_risk_ratio','threat_vuln_correlation','weighted_risk_score']
            self.weights = {
                'cvss_weight': 0.30,
                'vuln_weight': 0.15,
                'pii_weight': 0.20,
                'criticality_weight': 0.15,
                'exposure_weight': 0.10,
                'compliance_weight': 0.15,
                'threat_weight': 0.25
            }
        except Exception as e:
            st.error(f"Error loading SecureApp metadata: {e}")
            st.stop()
    def _load_model(self):
        try:
            with open('models/secureapp_model.pkl', 'rb') as f:
                self.classifier = pickle.load(f)
            with open('models/scaler.pkl', 'rb') as f:
                self.scaler = pickle.load(f)
        except FileNotFoundError:
            st.error("SecureApp model files not found in 'models' directory.")
            st.stop()
        except Exception as e:
            st.error(f"Error loading SecureApp model: {e}")
            st.stop()
    def predict_risk(self, app_data):
        if not self.classifier or not self.scaler:
            return {"error": "SecureApp model not loaded"}
        cvss_score = app_data.get('cvss_score', 5.0)
        vuln_count = app_data.get('vuln_count', 3)
        pii_exposure = 1 if app_data.get('pii_exposure') == 'Yes' else 0
        criticality = {'low': 0, 'medium': 0.5, 'high': 1.0, 'critical': 1.5}.get(app_data.get('criticality', 'medium'), 0.5)
        exposure = 1 if app_data.get('exposure') == 'external' else 0
        compliance_score = app_data.get('compliance_score', 75)
        threat_severity = min(1.0, (cvss_score / 10.0) * (1 + criticality))
        cvss_vuln_interaction = cvss_score * vuln_count / 10.0
        pii_exposure_risk = pii_exposure * (1 + criticality)
        external_pii_risk = exposure * pii_exposure * cvss_score / 10.0
        compliance_risk_ratio = (100 - compliance_score) / 100.0
        threat_vuln_correlation = threat_severity * vuln_count / 10.0
        weighted_risk_score = (cvss_score * 0.3 + vuln_count * 0.15 + pii_exposure * 20 * 0.2 + criticality * 25 * 0.15 + exposure * 15 * 0.1 + compliance_risk_ratio * 100 * 0.15)
        feature_values = {'cvss_score': cvss_score,'vuln_count': vuln_count,'pii_exposure': pii_exposure,'criticality': criticality,'exposure': exposure,'compliance_score': compliance_score,'threat_severity': threat_severity,'cvss_vuln_interaction': cvss_vuln_interaction,'pii_exposure_risk': pii_exposure_risk,'external_pii_risk': external_pii_risk,'compliance_risk_ratio': compliance_risk_ratio,'threat_vuln_correlation': threat_vuln_correlation,'weighted_risk_score': weighted_risk_score}
        try:
            features = np.array([feature_values[name] for name in self.feature_names]).reshape(1, -1)
            features_scaled = self.scaler.transform(features)
            risk_prob = self.classifier.predict_proba(features_scaled)[0][1]
        except Exception:
            # fallback: simple weighted combination
            risk_prob = weighted_risk_score / 100.0
        risk_score = risk_prob * 100
        if risk_score >= 80:
            risk_rating = "Critical"
        elif risk_score >= 60:
            risk_rating = "High"
        elif risk_score >= 40:
            risk_rating = "Medium"
        else:
            risk_rating = "Low"
        breakdown = {
            'CVSS Score': risk_score * self.weights.get('cvss_weight',0.3),
            'Exposure': risk_score * self.weights.get('exposure_weight',0.1),
            'Criticality': risk_score * self.weights.get('criticality_weight',0.15),
            'Compliance': risk_score * self.weights.get('compliance_weight',0.15),
            'PII Exposure': risk_score * self.weights.get('pii_weight',0.2)
        }
        return {
            'risk_score': round(risk_score, 2),
            'risk_rating': risk_rating,
            'breakdown': breakdown,
            'controls_compliance': compliance_score,
            'cis_compliance': min(85, compliance_score + 10),
            'threat_severity': risk_prob
        }

# --- AI Threat Detection: Log Analysis ---
# Feature extraction for CloudTrail logs
def extract_features(df, encoders=None):
    df_feat = df.copy()
    if 'eventTime' in df_feat.columns:
        df_feat['eventTime'] = pd.to_datetime(df_feat['eventTime'], errors='coerce')
        df_feat['hour'] = df_feat['eventTime'].dt.hour
        df_feat['day_of_week'] = df_feat['eventTime'].dt.dayofweek
        df_feat['is_weekend'] = df_feat['day_of_week'].isin([5,6]).astype(int)
        df_feat['is_night'] = ((df_feat['hour'] >=22)|(df_feat['hour']<=6)).astype(int)
    else:
        df_feat['hour']=12; df_feat['day_of_week']=1; df_feat['is_weekend']=0; df_feat['is_night']=0
    if 'sourceIPAddress' in df_feat.columns:
        def is_private_ip(ip):
            if pd.isna(ip) or not isinstance(ip,str): return 0
            private_patterns=[r'^10\.',r'^192\.168\.',r'^172\.(1[6-9]|2[0-9]|3[0-1])\.']
            return int(any(re.match(p,ip) for p in private_patterns))
        df_feat['is_private_ip']=df_feat['sourceIPAddress'].apply(is_private_ip)
        df_feat['is_external_ip']=(~df_feat['sourceIPAddress'].apply(lambda x: is_private_ip(x)==1)).astype(int)
        def get_first_octet(ip):
            if pd.isna(ip) or not isinstance(ip,str): return 0
            try: return int(ip.split('.')[0])
            except: return 0
        df_feat['ip_first_octet']=df_feat['sourceIPAddress'].apply(get_first_octet)
    else:
        df_feat['is_private_ip']=0; df_feat['is_external_ip']=0; df_feat['ip_first_octet']=0
    if 'userAgent' in df_feat.columns:
        df_feat['user_agent_length']=df_feat['userAgent'].fillna('').astype(str).str.len()
        df_feat['is_boto3']=df_feat['userAgent'].fillna('').str.contains('boto3',case=False).astype(int)
        df_feat['is_console']=df_feat['userAgent'].fillna('').str.contains('console',case=False).astype(int)
        df_feat['is_cli']=df_feat['userAgent'].fillna('').str.contains('aws-cli',case=False).astype(int)
        suspicious_patterns=['nmap','nessus','metasploit','sqlmap','python','curl','wget']
        df_feat['suspicious_user_agent']=df_feat['userAgent'].fillna('').apply(lambda x: any(p in x.lower() for p in suspicious_patterns)).astype(int)
    else:
        df_feat['user_agent_length']=0; df_feat['is_boto3']=0; df_feat['is_console']=0; df_feat['is_cli']=0; df_feat['suspicious_user_agent']=0
    if 'errorCode' in df_feat.columns:
        df_feat['has_error']=df_feat['errorCode'].notna().astype(int)
        df_feat['is_access_denied']=df_feat['errorCode'].fillna('').str.contains('AccessDenied',case=False).astype(int)
    else:
        df_feat['has_error']=0; df_feat['is_access_denied']=0
    if 'eventName' in df_feat.columns:
        df_feat['is_create_event']=df_feat['eventName'].fillna('').str.contains('Create',case=False).astype(int)
        df_feat['is_delete_event']=df_feat['eventName'].fillna('').str.contains('Delete',case=False).astype(int)
        df_feat['is_list_event']=df_feat['eventName'].fillna('').str.contains('List|Describe',case=False).astype(int)
        df_feat['is_admin_event']=df_feat['eventName'].fillna('').str.contains('Admin|Root|Policy',case=False).astype(int)
        sensitive_apis=['CreateUser','AttachUserPolicy','CreateRole','AssumeRole','GetSessionToken','PutBucketPolicy','ModifyDBInstance','RunInstances','AuthorizeSecurityGroupIngress','CreateSnapshot']
        df_feat['is_sensitive_api']=df_feat['eventName'].fillna('').apply(lambda x: x in sensitive_apis).astype(int)
        if encoders and 'eventName' in encoders:
            df_feat['eventName_encoded']=df_feat['eventName'].apply(lambda x: encoders['eventName'].transform([x])[0] if x in encoders['eventName'].classes_ else -1)
        else: df_feat['eventName_encoded']=0
    else:
        df_feat['is_create_event']=0; df_feat['is_delete_event']=0; df_feat['is_list_event']=0; df_feat['is_admin_event']=0; df_feat['is_sensitive_api']=0; df_feat['eventName_encoded']=0
    if 'eventSource' in df_feat.columns and encoders and 'eventSource' in encoders:
        df_feat['eventSource_encoded']=df_feat['eventSource'].apply(lambda x: encoders['eventSource'].transform([x])[0] if x in encoders['eventSource'].classes_ else -1)
    else: df_feat['eventSource_encoded']=0
    if 'awsRegion' in df_feat.columns and encoders and 'awsRegion' in encoders:
        df_feat['awsRegion_encoded']=df_feat['awsRegion'].apply(lambda x: encoders['awsRegion'].transform([x])[0] if x in encoders['awsRegion'].classes_ else -1)
    else: df_feat['awsRegion_encoded']=0
    df_feat = df_feat.fillna(0)
    return df_feat

def generate_synthetic_cloudtrail_data(num_events=1000):
    normal_events=[]; attack_events=[]
    normal_apis=['DescribeInstances','ListBuckets','GetObject','PutObject','DescribeSecurityGroups','DescribeVpcs','GetUser','ListRoles']
    attack_apis=['CreateUser','AttachUserPolicy','CreateRole','AssumeRole','GetSessionToken','PutBucketPolicy','ModifyDBInstance','RunInstances','AuthorizeSecurityGroupIngress','CreateSnapshot']
    for i in range(int(num_events*0.7)):
        event={
            'eventTime': (datetime.now()-timedelta(days=np.random.randint(1,30))).isoformat(),
            'eventName': np.random.choice(normal_apis), 'sourceIPAddress': f"10.0.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
            'userAgent':'aws-cli/2.0.0 Python/3.8.0','errorCode': None if np.random.random()>0.1 else 'AccessDenied',
            'responseElements': {'success':True} if np.random.random()>0.1 else None,
            'requestParameters': {'region':'us-east-1'}, 'recipientAccountId':'123456789012','awsRegion':'us-east-1', 'eventSource':f"{np.random.choice(['ec2','s3','iam','rds'])}.amazonaws.com",
            'threat_label': 0, 'risk_score': np.random.uniform(0,30)
        }
        normal_events.append(event)
    attack_scenarios=['privilege_escalation','credential_theft','data_exfiltration','reconnaissance','persistence','lateral_movement']
    for i in range(int(num_events*0.3)):
        scenario=np.random.choice(attack_scenarios)
        if scenario=='privilege_escalation':
            event={'eventTime':(datetime.now()-timedelta(hours=np.random.randint(1,48))).isoformat(),'eventName':np.random.choice(['CreateUser','AttachUserPolicy','CreateRole']),'sourceIPAddress':f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}",'userAgent':'Boto3/1.0.0','errorCode':None,'responseElements':{'success':True},'requestParameters':{'userName':f'temp-user-{i}','policyArn':'arn:aws:iam::aws:policy/AdministratorAccess'},'recipientAccountId':'123456789012','awsRegion':'us-east-1','eventSource':'iam.amazonaws.com','attack_scenario':scenario,'threat_label':1,'risk_score':np.random.uniform(70,95)}
        elif scenario=='data_exfiltration':
            event={'eventTime':(datetime.now()-timedelta(hours=np.random.randint(1,24))).isoformat(),'eventName':np.random.choice(['GetObject','ListBuckets','PutBucketPolicy']),'sourceIPAddress':f"203.0.{np.random.randint(1,255)}.{np.random.randint(1,255)}",'userAgent':'python-requests/2.25.1','errorCode':None,'responseElements':{'bytesTransferred':np.random.randint(1000000,10000000)},'requestParameters':{'bucketName':'sensitive-data-bucket'},'recipientAccountId':'123456789012','awsRegion':'us-east-1','eventSource':'s3.amazonaws.com','attack_scenario':scenario,'threat_label':1,'risk_score':np.random.uniform(80,98)}
        else:
            event={'eventTime':(datetime.now()-timedelta(hours=np.random.randint(1,12))).isoformat(),'eventName':np.random.choice(['DescribeInstances','ListUsers','GetUser','DescribeSecurityGroups']),'sourceIPAddress':f"45.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}",'userAgent':'aws-cli/1.18.0','errorCode':'AccessDenied' if np.random.random()>0.7 else None,'responseElements':None if np.random.random()>0.7 else {'instancesSet':[]},'requestParameters':{'maxResults':1000},'recipientAccountId':'123456789012','awsRegion':'us-east-1','eventSource':f"{np.random.choice(['ec2','iam'])}.amazonaws.com",'attack_scenario':scenario,'threat_label':1,'risk_score':np.random.uniform(60,85)}
        attack_events.append(event)
    all_events=normal_events+attack_events
    np.random.shuffle(all_events)
    return pd.DataFrame(all_events)

# --- Load or Mock Models ---
@st.cache_resource
def load_threat_model():
    model_path = 'aws_threat_detection_model.pkl'
    current_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths = [model_path, os.path.join(current_dir, model_path)]
    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    model = pickle.load(f)
                return {'model': model, 'feature_columns': None, 'label_encoders': None}
            except Exception:
                continue
    st.info("Threat detection model not found; using mock model.")
    mock_model = RandomForestClassifier(n_estimators=10, random_state=42)
    feature_cols = ['hour','day_of_week','is_weekend','is_night','is_private_ip','ip_first_octet','user_agent_length','is_boto3','is_console','is_cli','has_error','is_access_denied','is_create_event','is_delete_event','is_list_event','is_admin_event','is_external_ip','is_sensitive_api','suspicious_user_agent','eventName_encoded','eventSource_encoded','awsRegion_encoded']
    X_mock = np.random.rand(100, len(feature_cols)); y_mock = np.random.randint(0,2,100)
    mock_model.fit(X_mock, y_mock)
    # Mock encoders
    encoders = {'eventName': LabelEncoder(), 'eventSource': LabelEncoder(), 'awsRegion': LabelEncoder()}
    encoders['eventName'].fit(['AssumeRole','GetSessionToken','CreateUser','DeleteUser','ListUsers','RunInstances','StopInstances','StartInstances','TerminateInstances','DescribeInstances','CreateBucket','DeleteBucket','PutObject','GetObject','ListBuckets'])
    encoders['eventSource'].fit(['iam.amazonaws.com','sts.amazonaws.com','s3.amazonaws.com','ec2.amazonaws.com','cloudtrail.amazonaws.com'])
    encoders['awsRegion'].fit(['us-east-1','us-east-2','us-west-1','us-west-2','eu-west-1'])
    return {'model': mock_model, 'feature_columns': feature_cols, 'label_encoders': encoders}

threat_pkg = load_threat_model()
rf_model = threat_pkg['model']
feature_columns = threat_pkg.get('feature_columns')
encoders = threat_pkg.get('label_encoders')

# Prediction helper for threat analysis
def predict_df(df_events):
    try:
        df_feat = extract_features(df_events, encoders)
        if feature_columns:
            X = df_feat[feature_columns]
        else:
            X = df_feat.select_dtypes(include=[np.number]).fillna(0)
        if X.isnull().any().any():
            X = X.fillna(0)
        probs = rf_model.predict_proba(X)[:,1] if hasattr(rf_model, 'predict_proba') else rf_model.predict(X)
        preds = rf_model.predict(X)
        return preds, probs
    except Exception as e:
        st.error(f"Prediction error: {e}")
        return np.zeros(len(df_events)), np.zeros(len(df_events))

def parse_json_file(uploaded_file):
    try:
        content = uploaded_file.read()
        if isinstance(content, bytes): content = content.decode('utf-8')
        data = json.loads(content)
        if isinstance(data, dict):
            if 'Records' in data: return pd.DataFrame(data['Records'])
            else: return pd.DataFrame([data])
        elif isinstance(data, list): return pd.DataFrame(data)
        else: st.error("Unsupported JSON format"); return None
    except Exception as e:
        st.error(f"Error parsing JSON: {e}"); return None

def get_risk_level_info(probability):
    if probability >= 0.8: return "🔴 CRITICAL", "threat-critical"
    elif probability >= 0.6: return "🟠 HIGH", "threat-high"
    elif probability >= 0.4: return "🟡 MEDIUM", "threat-medium"
    else: return "🟢 LOW", "threat-low"

# Initialize SecureAppModel in session
if 'secure_model' not in st.session_state:
    try:
        st.session_state.secure_model = SecureAppModel()
    except Exception:
        st.session_state.secure_model = None

if 'assessment_history' not in st.session_state:
    st.session_state.assessment_history = []

# Main header
st.markdown('<div class="main-header"><h1>Unified Dashboard</h1></div>', unsafe_allow_html=True)

# Create main tabs
tab1, tab2 = st.tabs(["Application Risk Assessment", "Log Analysis"] )

# --- Tab: Application Risk Assessment ---
with tab1:
    st.markdown("## 🔍 Application Risk Assessment")
    with st.form("assessment_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        with col1:
            app_id = st.text_input("Application ID", placeholder="e.g., APP001")
            criticality = st.selectbox("Business Criticality", ["low","medium","high","critical"])
            pii_exposure = st.selectbox("PII Exposure", ["No","Yes"])
        with col2:
            exposure = st.selectbox("Network Exposure", ["internal","external"])
            cvss_score = st.slider("Average CVSS Score", 0.0, 10.0, 5.0, 0.1)
            vuln_count = st.number_input("Vulnerability Count", min_value=0, max_value=100, value=3)
            compliance_score = st.slider("Compliance Score (%)", 0, 100, 75)
        submit = st.form_submit_button("🚀 Assess Risk")
        if submit:
            if not app_id:
                st.error("Application ID is required!")
            else:
                if st.session_state.secure_model is None:
                    st.error("SecureApp model not initialized.")
                else:
                    app_data = {'app_id':app_id,'criticality':criticality,'pii_exposure':pii_exposure,'exposure':exposure,'cvss_score':cvss_score,'vuln_count':vuln_count,'compliance_score':compliance_score}
                    with st.spinner("Analyzing application risk..."):
                        time.sleep(0.5)
                        result = st.session_state.secure_model.predict_risk(app_data)
                    if 'error' not in result:
                        record = {**app_data, **result, 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                        st.session_state.assessment_history.append(record)
                        st.success(f"Assessment completed for {app_id}")
                        risk_class = f"risk-{result['risk_rating'].lower()}"
                        st.markdown(f"<div class='material-card {risk_class}'><h3>Risk: {result['risk_rating']} ({result['risk_score']}/100)</h3></div>", unsafe_allow_html=True)
                        met1,met2,met3,met4 = st.columns(4)
                        met1.metric("Compliance Score", f"{result['controls_compliance']:.1f}%")
                        met2.metric("CIS Compliance", f"{result['cis_compliance']:.1f}%")
                        met3.metric("Threat Severity", f"{result['threat_severity']:.2f}")
                        met4.metric("Vulnerabilities", vuln_count)
                        # Breakdown chart
                        st.markdown("### Risk Factor Breakdown")
                        df_break = pd.DataFrame([{"Factor":k,"Contribution":v} for k,v in result['breakdown'].items()])
                        fig = px.bar(df_break, x="Factor", y="Contribution", title="Risk Breakdown", color="Contribution", color_continuous_scale="RdYlBu_r")
                        st.plotly_chart(fig, use_container_width=True)
                        # Recommendations
                        st.markdown("### Recommendations")
                        if result['risk_rating']=='Critical': st.error("🚨 Immediate action required!"); st.markdown("- Implement controls immediately\n- Conduct thorough review")
                        elif result['risk_rating']=='High': st.warning("⚠️ High priority"); st.markdown("- Schedule assessment\n- Review policies")
                        elif result['risk_rating']=='Medium': st.info("Monitor closely"); st.markdown("- Regular monitoring\n- Quarterly review")
                        else: st.success("Good posture"); st.markdown("- Continue practices\n- Annual review")
                    else:
                        st.error(f"Assessment failed: {result.get('error')}")
    # Dashboard inside tab
    st.markdown("---")
    st.markdown("## 📊 Assessment Dashboard")
    if st.session_state.assessment_history:
        df_hist = pd.DataFrame(st.session_state.assessment_history)
        c1,c2,c3,c4 = st.columns(4)
        c1.metric("Total Assessments", len(df_hist))
        c2.metric("Average Risk Score", f"{df_hist['risk_score'].mean():.1f}")
        c3.metric("Critical Applications", len(df_hist[df_hist['risk_rating']=='Critical']))
        c4.metric("High Risk Applications", len(df_hist[df_hist['risk_rating']=='High']))
        # Distribution
        col1, col2 = st.columns(2)
        with col1:
            counts = df_hist['risk_rating'].value_counts()
            fig_pie = px.pie(values=counts.values, names=counts.index, title="Risk Distribution")
            st.plotly_chart(fig_pie, use_container_width=True)
        with col2:
            scores = pd.to_numeric(df_hist['risk_score'],errors='coerce').dropna()
            if not scores.empty:
                fig_hist = px.histogram(x=scores, nbins=20, title="Risk Score Distribution")
                st.plotly_chart(fig_hist, use_container_width=True)
        st.markdown("### Recent Assessments")
        st.dataframe(df_hist[['app_id','risk_rating','risk_score','criticality','exposure','timestamp']].tail(10), use_container_width=True)
    else:
        st.info("No assessments yet.")

# --- Tab: Log Analysis ---
with tab2:
    st.markdown("## 📊 AI Log Analysis")
    st.markdown("### Batch Log Analysis")
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    uploaded = st.file_uploader("Upload CloudTrail log (JSON or CSV)", type=['json','csv'], key="batch_upload")
    if uploaded:
        try:
            st.info(f"File: {uploaded.name} ({uploaded.size} bytes)")
            if uploaded.name.endswith('.json'):
                df = parse_json_file(uploaded)
            else:
                df = pd.read_csv(uploaded)
            if df is not None and not df.empty:
                st.success(f"Loaded {len(df)} records")
                with st.expander("Data Preview", expanded=False): st.dataframe(df.head(10), use_container_width=True)
                with st.spinner("Analyzing threats..."):
                    preds, probs = predict_df(df)
                    df['prediction'] = preds; df['threat_probability'] = probs; df['risk_level']=[get_risk_level_info(p)[0] for p in probs]
                c1,c2,c3,c4 = st.columns(4)
                c1.markdown(f'<div class="material-card"><div class="material-metric-label">Total Events</div><div class="material-metric-value">{len(df)}</div></div>', unsafe_allow_html=True)
                c2.markdown(f'<div class="material-card threat-critical"><div class="material-metric-label">Threats Detected</div><div class="material-metric-value">{sum(preds)}</div></div>', unsafe_allow_html=True)
                c3.markdown(f'<div class="material-card"><div class="material-metric-label">Average Risk</div><div class="material-metric-value">{np.mean(probs):.1%}</div></div>', unsafe_allow_html=True)
                c4.markdown(f'<div class="material-card threat-medium"><div class="material-metric-label">High Risk Events</div><div class="material-metric-value">{sum(probs>=0.6)}</div></div>', unsafe_allow_html=True)
                st.subheader("Analysis Results")
                col1, col2 = st.columns(2)
                with col1: show_threats_only = st.checkbox("Show threats only", value=False)
                with col2: min_prob = st.slider("Minimum threat probability", 0.0, 1.0, 0.0, 0.1)
                df_filtered = df.copy()
                if show_threats_only: df_filtered = df_filtered[df_filtered['prediction']==1]
                df_filtered = df_filtered[df_filtered['threat_probability']>=min_prob]
                df_filtered = df_filtered.sort_values('threat_probability', ascending=False)
                st.dataframe(df_filtered, use_container_width=True)
                csv = df_filtered.to_csv(index=False)
                st.download_button("Download Results as CSV", data=csv, file_name=f"threat_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
            else:
                st.error("Failed to load data")
        except Exception as e:
            st.error(f"Error processing file: {e}")
    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("### Data Visualization & Synthetic Data")
    if st.button("Generate Sample Data for Visualization"):
        with st.spinner("Generating..."):
            viz_df = generate_synthetic_cloudtrail_data(1000)
            # Visualizations
            st.markdown('<div class="chart-container">', unsafe_allow_html=True)
            # Threat distribution
            threat_counts = viz_df['threat_label'].value_counts()
            fig1 = px.pie(values=threat_counts.values, names=['Normal','Threat'], title="Threat Distribution")
            st.plotly_chart(fig1, use_container_width=True)
            # Risk histogram
            fig2 = px.histogram(x=viz_df['risk_score'], nbins=20, title="Risk Score Distribution")
            st.plotly_chart(fig2, use_container_width=True)
            # Timeline
            viz_df['eventTime'] = pd.to_datetime(viz_df['eventTime'])
            timeline = viz_df.groupby(viz_df['eventTime'].dt.date)['threat_label'].sum().reset_index()
            fig3 = px.line(timeline, x='eventTime', y='threat_label', title="Daily Threats")
            st.plotly_chart(fig3, use_container_width=True)
            # Top attack APIs
            top_apis = viz_df[viz_df['threat_label']==1]['eventName'].value_counts().head(5)
            fig4 = px.bar(x=top_apis.index, y=top_apis.values, title="Top Attack APIs")
            st.plotly_chart(fig4, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
            # Additional
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("IP Address Analysis")
                ip_analysis = viz_df.groupby('threat_label')['sourceIPAddress'].apply(lambda x: x.str.startswith(('10.','192.168.')).sum()).reset_index()
                ip_analysis.columns=['threat_label','private_ip_count']
                ip_analysis['type']=ip_analysis['threat_label'].map({0:'Normal',1:'Threat'})
                fig_ip = px.bar(ip_analysis, x='type', y='private_ip_count', title="Private IP Usage by Threat Type")
                st.plotly_chart(fig_ip, use_container_width=True)
            with col2:
                st.subheader("Event Source Analysis")
                source_analysis = viz_df.groupby(['eventSource','threat_label']).size().reset_index(name='count')
                source_analysis['type']=source_analysis['threat_label'].map({0:'Normal',1:'Threat'})
                fig_src = px.bar(source_analysis, x='eventSource', y='count', color='type', title="Events by Source & Threat")
                st.plotly_chart(fig_src, use_container_width=True)
            st.subheader("Data Summary")
            c1,c2,c3,c4 = st.columns(4)
            c1.markdown(f'<div class="material-card"><div class="material-metric-label">Total Events</div><div class="material-metric-value">{len(viz_df)}</div></div>', unsafe_allow_html=True)
            c2.markdown(f'<div class="material-card"><div class="material-metric-label">Normal Events</div><div class="material-metric-value">{len(viz_df[viz_df["threat_label"]==0])}</div></div>', unsafe_allow_html=True)
            c3.markdown(f'<div class="material-card threat-critical"><div class="material-metric-label">Threat Events</div><div class="material-metric-value">{len(viz_df[viz_df["threat_label"]==1])}</div></div>', unsafe_allow_html=True)
            threat_rate = len(viz_df[viz_df['threat_label']==1]) / len(viz_df) * 100
            c4.markdown(f'<div class="material-card"><div class="material-metric-label">Threat Rate</div><div class="material-metric-value">{threat_rate:.1f}%</div></div>', unsafe_allow_html=True)
