
import os
import math
import re
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

# ----- Config -----
MODEL_PATH = "phishguard_url_model.pkl"
FEATURES_PATH = "feature_columns.pkl"
DEFAULT_THRESHOLD = 0.5  # probability cutoff to consider phishing

# ----- App init -----
app = Flask(__name__)
CORS(app)

# ----- Load model & feature order -----
if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
    raise FileNotFoundError("Model or feature_columns missing. Run url_model_trainer.py first.")

model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(FEATURES_PATH)
USE_PROBA = hasattr(model, "predict_proba")
print(f"Loaded model: {MODEL_PATH} (predict_proba: {USE_PROBA})")
print("Feature columns:", feature_columns)

# ----- Feature extraction (must match trainer) -----
SUSPICIOUS_WORDS = [
    'secure','account','update','login','verify','confirm','bank','paypal','signin','support','ebay','amazon'
]

def get_url_length(url):
    return len(url or "")

def get_hostname_length(url):
    try:
        return len(urlparse(url).netloc)
    except Exception:
        return 0

def has_ip_address(url):
    domain = (urlparse(url).netloc or "").split(':')[0]
    return 1 if re.search(r"^(?:\d{1,3}\.){3}\d{1,3}$", domain) else 0

def count_dots(url):
    return (url or "").count('.')

def count_hyphens(url):
    return (url or "").count('-')

def count_at_symbol(url):
    return (url or "").count('@')

def count_digits(url):
    return sum(c.isdigit() for c in (url or ""))

def count_params(url):
    s = url or ""
    return s.count('?') + s.count('&') + s.count('=')

def contains_suspicious_word(url):
    u = (url or "").lower()
    return 1 if any(w in u for w in SUSPICIOUS_WORDS) else 0

def has_https(url):
    return 1 if (url or "").lower().startswith("https") else 0

def num_subdomains(url):
    hostname = urlparse(url).netloc or ""
    if ':' in hostname:
        hostname = hostname.split(':')[0]
    parts = [p for p in hostname.split('.') if p]
    return max(0, len(parts) - 2)

def hostname_entropy(url):
    h = urlparse(url).netloc or ""
    if len(h) == 0:
        return 0.0
    counts = {}
    for c in h:
        counts[c] = counts.get(c, 0) + 1
    probs = [v / len(h) for v in counts.values()]
    return float(-sum(p * math.log2(p) for p in probs)) if probs else 0.0

# Additional features
def path_length(url):
    try:
        return len(urlparse(url).path or "")
    except Exception:
        return 0

def query_length(url):
    try:
        return len(urlparse(url).query or "")
    except Exception:
        return 0

def ratio_digits_to_length(url):
    l = get_url_length(url)
    if l == 0:
        return 0.0
    return float(count_digits(url)) / float(l)

def extract_features_dict(url):
    return {
        "url_length": get_url_length(url),
        "hostname_length": get_hostname_length(url),
        "has_ip_address": has_ip_address(url),
        "num_dots": count_dots(url),
        "num_hyphens": count_hyphens(url),
        "num_at": count_at_symbol(url),
        "num_digits": count_digits(url),
        "num_params": count_params(url),
        "suspicious_words": contains_suspicious_word(url),
        "has_https": has_https(url),
        "num_subdomains": num_subdomains(url),
        "hostname_entropy": hostname_entropy(url),
        "path_length": path_length(url),
        "query_length": query_length(url),
        "ratio_digits_to_length": ratio_digits_to_length(url)
    }

def feature_vector_from_dict(d):
    return [float(d.get(col, 0.0)) for col in feature_columns]

# ----- Helper: phishing probability from predict_proba -----
def phishing_probability_from_proba(probas):
    if not USE_PROBA:
        return None
    classes = list(getattr(model, "classes_", []))
    if 0 in classes:
        idx = classes.index(0)
        return float(probas[0][idx])
    return float(probas[0][0])

# ----- Prediction wrapper -----
def do_predict(url, threshold=DEFAULT_THRESHOLD):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    features = extract_features_dict(url)
    vec = feature_vector_from_dict(features)

    try:
        if USE_PROBA:
            proba = model.predict_proba([vec])
            phishing_prob = phishing_probability_from_proba(proba)
        else:
            pred = int(model.predict([vec])[0])
            phishing_prob = 1.0 if pred == 0 else 0.0
    except Exception as e:
        raise RuntimeError(f"Model prediction failed: {e}")

    is_phishing = bool(phishing_prob >= threshold)
    return {
        "is_phishing": is_phishing,
        "phishing_score": float(phishing_prob),
        "features": features,
        "feature_order": feature_columns
    }

# ----- Routes -----
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_loaded": True}), 200

@app.route("/analyze", methods=["POST"])
@app.route("/predict", methods=["POST"])
def analyze():
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify({"error": "invalid_json"}), 400

    url = payload.get("url") or payload.get("u") or payload.get("target_url") or ""
    if not url:
        return jsonify({"error": "url_missing"}), 400

    try:
        result = do_predict(str(url))
    except Exception as e:
        return jsonify({"error": "model_error", "detail": str(e)}), 500

    return jsonify(result), 200

# ----- Runner -----
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
