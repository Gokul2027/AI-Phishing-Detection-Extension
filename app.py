# app.py
"""
Flask scoring server for PhishGuard URL model.

Run:
    python app.py
The Chrome extension should POST JSON: { "url": "https://example.com" }
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re
from urllib.parse import urlparse
import math

# -----------------------
# Feature extraction functions (MUST be identical to url_model_trainer.py)
# -----------------------
def get_url_length(url):
    return len(url)

def get_hostname_length(url):
    try:
        return len(urlparse(url).netloc)
    except Exception:
        return 0

def has_ip_address(url):
    domain = urlparse(url).netloc
    return 1 if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", domain) else 0

def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def count_at_symbol(url):
    return url.count('@')

def count_digits(url):
    return sum(c.isdigit() for c in url)

def count_params(url):
    return url.count('?') + url.count('&') + url.count('=')

SUSPICIOUS_WORDS = [
    'secure','account','update','login','verify','confirm','bank','paypal','signin','support','ebay','amazon'
]

def contains_suspicious_word(url):
    url_low = url.lower()
    return 1 if any(word in url_low for word in SUSPICIOUS_WORDS) else 0

def has_https(url):
    return 1 if url.lower().startswith("https") else 0

def num_subdomains(url):
    hostname = urlparse(url).netloc
    parts = hostname.split('.')
    if ':' in parts[-1]:
        parts[-1] = parts[-1].split(':')[0]
    return max(0, len(parts) - 2)

def hostname_entropy(url):
    hostname = urlparse(url).netloc
    if len(hostname) == 0:
        return 0.0
    counts = {}
    for c in hostname:
        counts[c] = counts.get(c, 0) + 1
    probs = [v / len(hostname) for v in counts.values()]
    ent = -sum(p * math.log2(p) for p in probs)
    return ent

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
        "hostname_entropy": hostname_entropy(url)
    }

# -----------------------
# App setup + model load
# -----------------------
app = Flask(__name__)
CORS(app)

MODEL_PATH = "phishguard_url_model.pkl"
FEATURES_PATH = "feature_columns.pkl"

try:
    model = joblib.load(MODEL_PATH)
    feature_columns = joblib.load(FEATURES_PATH)
    print("Model & feature columns loaded.")
except Exception as e:
    print("Failed to load model or feature columns:", e)
    raise

# If model has predict_proba, use that, otherwise fallback to predict
USE_PROBA = hasattr(model, "predict_proba")

# Default threshold to flag phishing (you can tune this)
PHISHING_THRESHOLD = 0.5  # probability of class 0 (phishing) or we invert depending on classifier ordering

# Determine which class index corresponds to phishing (label 0 vs 1)
# We assume training labels: 1 = legit, 0 = phishing (as used in trainer)
# predict_proba returns probabilities in the order of model.classes_
def phishing_probability_from_proba(probas):
    """
    Return phishing probability (higher => more likely phishing)
    We trained label=0 for phishing and label=1 for legit.
    So if classes_ == [0,1], proba for index 0 is phishing_prob.
    """
    if not USE_PROBA:
        return None
    classes = list(getattr(model, "classes_", []))
    if len(classes) == 0:
        # fallback: assume index 0 => class 0 (phishing)
        return probas[0][0]
    try:
        idx = classes.index(0)
        return probas[0][idx]
    except ValueError:
        # class 0 not found; maybe model trained with reversed labels; assume phishing=1
        try:
            idx = classes.index(1)
            return probas[0][idx]
        except ValueError:
            return probas[0][0]

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_loaded": True}), 200

@app.route("/analyze", methods=["POST"])
def analyze():
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify({"error": "invalid_json"}), 400
    url = payload.get("url") or payload.get("u") or ""
    if not url:
        return jsonify({"error": "url_missing"}), 400

    # Basic sanitization
    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        # Try to normalize
        url = "http://" + url

    # Extract features (use same order as FEATURE_COLUMNS)
    features_dict = extract_features_dict(url)
    # Build feature vector in correct order
    feature_vector = [features_dict.get(col, 0) for col in feature_columns]

    # Predict
    try:
        if USE_PROBA:
            proba = model.predict_proba([feature_vector])
            phishing_prob = phishing_probability_from_proba(proba)
            # If the model used inverted labels (rare), phishing_prob may represent legit. You can re-check with sample cases.
        else:
            pred = model.predict([feature_vector])[0]
            # if predict returns 0 or 1 (we choose 0=phishing), set phishing_prob accordingly
            phishing_prob = 1.0 if pred == 0 else 0.0
    except Exception as e:
        return jsonify({"error": "model_prediction_failed", "detail": str(e)}), 500

    # Decide phishing flag by threshold
    is_phishing = True if phishing_prob >= PHISHING_THRESHOLD else False

    response = {
        "is_phishing": bool(is_phishing),
        "phishing_score": float(phishing_prob),
        "features": features_dict,
        "feature_order": feature_columns
    }
    return jsonify(response), 200

if __name__ == "__main__":
    # For development only. Use a production WSGI server in production.
    app.run(host="127.0.0.1", port=5000, debug=True)
