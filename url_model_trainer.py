# url_model_trainer.py
"""
Train a stronger phishing URL model and save model + feature order.

Requirements:
    pip install pandas scikit-learn xgboost joblib
If xgboost isn't available the script will use RandomForest automatically.
"""

import pandas as pd
import numpy as np
import re
import math
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from sklearn.ensemble import RandomForestClassifier
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except Exception:
    XGBOOST_AVAILABLE = False
    print("xgboost not available — falling back to RandomForestClassifier")

# -----------------------
# Feature extraction (MUST match app.py)
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
    # count of query parameters (rough)
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
    # remove port if present
    if ':' in parts[-1]:
        parts[-1] = parts[-1].split(':')[0]
    # subdomains = total parts minus (domain + tld)
    return max(0, len(parts) - 2)

def hostname_entropy(url):
    hostname = urlparse(url).netloc
    if len(hostname) == 0:
        return 0.0
    counts = {}
    for c in hostname:
        counts[c] = counts.get(c, 0) + 1
    probs = [v / len(hostname) for v in counts.values()]
    # Shannon entropy
    ent = -sum(p * math.log2(p) for p in probs)
    return ent

def extract_features_row(url):
    """Return a dict of features for the URL"""
    return {
        "url": url,
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

FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "has_ip_address",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_digits",
    "num_params",
    "suspicious_words",
    "has_https",
    "num_subdomains",
    "hostname_entropy"
]

# -----------------------
# Load dataset
# -----------------------
CSV_PATH = "phishing_detection_dataset.csv"  # ensure file exists in working dir
print("Loading dataset:", CSV_PATH)
df = pd.read_csv(CSV_PATH)

if 'label' not in df.columns:
    raise RuntimeError("Dataset must contain 'label' column with 1=legit, 0=phishing")

# Drop rows with missing URL
df = df.dropna(subset=['url']).reset_index(drop=True)

# Extract features
print("Extracting features for", len(df), "rows...")
features = df['url'].apply(extract_features_row)
X_df = pd.DataFrame(list(features))
# keep only the feature columns
X = X_df[FEATURE_COLUMNS]
y = df['label'].astype(int)

# -----------------------
# Train/test split (time-based recommended in real pipelines)
# -----------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# -----------------------
# Model training
# -----------------------
if XGBOOST_AVAILABLE:
    print("Training XGBoost classifier...")
    model = xgb.XGBClassifier(
        n_estimators=400,
        max_depth=7,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        use_label_encoder=False,
        eval_metric='logloss',
        n_jobs=-1
    )
else:
    print("Training RandomForest classifier...")
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )

model.fit(X_train, y_train)
print("Training finished.")

# -----------------------
# Evaluation
# -----------------------
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary', pos_label=1)
print(f"Accuracy: {acc:.4f}")
print(f"Precision (legit=1): {precision:.4f}, Recall (legit=1): {recall:.4f}, F1: {f1:.4f}")
print("Classification report (label 0=phishing, 1=legit):\n")
print(classification_report(y_test, y_pred, digits=4))

# -----------------------
# Save model and feature columns (order matters)
# -----------------------
MODEL_PATH = "phishguard_url_model.pkl"
FEATURES_PATH = "feature_columns.pkl"

joblib.dump(model, MODEL_PATH)
joblib.dump(FEATURE_COLUMNS, FEATURES_PATH)
print(f"Saved model -> {MODEL_PATH}")
print(f"Saved feature column order -> {FEATURES_PATH}")
