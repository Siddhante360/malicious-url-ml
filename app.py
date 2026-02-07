import streamlit as st
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

# Load model and scaler
model = joblib.load("url_malware_rf_model.pkl")
scaler = joblib.load("url_scaler.pkl")

# Feature extraction function
def extract_url_features(url):
    parsed = urlparse(url)
    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_slashes": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "has_ip": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_at": 1 if "@" in url else 0,
        "has_exe": 1 if ".exe" in url.lower() else 0,
        "has_zip": 1 if ".zip" in url.lower() else 0,
        "num_special_chars": sum(url.count(c) for c in "-_?=&%")
    }

# UI
st.set_page_config(page_title="URL Malware Detector", layout="centered")

st.title("🔐 URL Malware Detection System")
st.write("Enter a URL to check whether it is **Benign** or **Malicious**.")

url_input = st.text_input("🔗 Enter URL")

if st.button("Predict"):
    if url_input.strip() == "":
        st.warning("Please enter a URL")
    else:
        features = extract_url_features(url_input)
        features_df = pd.DataFrame([features])
        features_scaled = scaler.transform(features_df)

        prediction = model.predict(features_scaled)[0]

        if prediction == 1:
            st.error("⚠️ This URL is MALICIOUS")
        else:
            st.success("✅ This URL is BENIGN")
