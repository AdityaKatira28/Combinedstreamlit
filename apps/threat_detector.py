import streamlit as st
import pandas as pd
import json
from core import BaseAppInterface
from models.threat_detector_model import ThreatDetectionModel

APP_NAME = "Log Analysis"
ICON = "📊"

class Interface(BaseAppInterface):
    def initialize(self):
        if 'threat_model' not in st.session_state:
            st.session_state.threat_model = ThreatDetectionModel()

    def render(self):
        st.markdown("## 📊 AI Log Analysis")
        uploaded = st.file_uploader("Upload CloudTrail log (JSON or CSV)", type=['json','csv'], key="batch_upload")
        if uploaded:
            try:
                if uploaded.name.endswith('.json'):
                    content = uploaded.read()
                    data = json.loads(content)
                    # If JSON has "Records": use data['Records']
                    records = data.get('Records', data) if isinstance(data, dict) else data
                    df = pd.DataFrame(records)
                else:
                    df = pd.read_csv(uploaded)
                if df is not None and not df.empty:
                    preds, probs = st.session_state.threat_model.predict_df(df)
                    df['prediction'] = preds
                    df['threat_probability'] = probs
                    # Display summary metrics
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Total Events", len(df))
                    c2.metric("Threats Detected", int((df['prediction']==1).sum()))
                    c3.metric("Average Risk", f"{df['threat_probability'].mean():.1%}")
                    c4.metric("High Risk Events", int((df['threat_probability']>=0.6).sum()))
                    # Dataframe view with filtering controls
                    show_threats_only = st.checkbox("Show threats only", value=False)
                    min_prob = st.slider("Minimum threat probability", 0.0, 1.0, 0.0, 0.1)
                    df_filtered = df.copy()
                    if show_threats_only:
                        df_filtered = df_filtered[df_filtered['prediction']==1]
                    df_filtered = df_filtered[df_filtered['threat_probability']>=min_prob]
                    df_filtered = df_filtered.sort_values('threat_probability', ascending=False)
                    st.dataframe(df_filtered, use_container_width=True)
                    # Download button
                    csv = df_filtered.to_csv(index=False)
                    from datetime import datetime
                    st.download_button("Download Results as CSV", data=csv, file_name=f"threat_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
                else:
                    st.error("Failed to load data")
            except Exception as e:
                st.error(f"Error processing file: {e}")
