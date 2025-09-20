
import os
import math
import re
import joblib
import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from sklearn.ensemble import RandomForestClassifier

# Optional imports
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except Exception:
    XGBOOST_AVAILABLE = False

try:
    from imblearn.over_sampling import SMOTE
    SMOTE_AVAILABLE = True
except Exception:
    SMOTE_AVAILABLE = False

# ----- Config / paths -----
CSV_PATH = "phishing_detection_dataset.csv"
MODEL_PATH = "phishguard_url_model.pkl"
FEATURES_SAVE_PATH = "feature_columns.pkl"
USE_SMOTE = True  # try to use SMOTE if available; safe fallback provided

# ----- Feature extraction (must match app.py) -----
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

# --- New additional features (still string-based, no network calls) ---
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

# Define feature column order — KEEP THIS ORDER; app.py must use same
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
    "hostname_entropy",
    # additional features
    "path_length",
    "query_length",
    "ratio_digits_to_length"
]

def extract_features_row(url):
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

# ----- Load dataset -----
if not os.path.exists(CSV_PATH):
    raise FileNotFoundError(f"Dataset not found: {CSV_PATH}. Place your CSV in the script folder.")

print("Loading dataset:", CSV_PATH)
df = pd.read_csv(CSV_PATH)

if 'url' not in df.columns or 'label' not in df.columns:
    raise RuntimeError("Dataset must include 'url' and 'label' columns (label: 0=phishing, 1=legit).")

# Ensure numeric labels 0/1
df['label'] = df['label'].astype(int)

# Basic stats
label_counts = df['label'].value_counts().to_dict()
print("Label distribution:", label_counts)

# Drop missing URLs
df = df.dropna(subset=['url']).reset_index(drop=True)
print("Rows after dropna:", len(df))

# ----- Feature extraction -----
print("Extracting features for all rows...")
feat_series = df['url'].apply(extract_features_row)
X_df = pd.DataFrame(list(feat_series))
X = X_df[FEATURE_COLUMNS].copy()
y = df['label'].astype(int)

print("Feature matrix shape:", X.shape)

# ----- Balance using SMOTE if available and requested -----
if USE_SMOTE and SMOTE_AVAILABLE:
    try:
        print("Applying SMOTE to balance classes...")
        sm = SMOTE(random_state=42)
        X_res, y_res = sm.fit_resample(X, y)
        X = pd.DataFrame(X_res, columns=FEATURE_COLUMNS)
        y = pd.Series(y_res)
        print("After SMOTE label distribution:", y.value_counts().to_dict())
    except Exception as e:
        print("SMOTE failed, continuing without SMOTE:", e)
else:
    if USE_SMOTE and not SMOTE_AVAILABLE:
        print("SMOTE requested but imblearn not installed. Skipping SMOTE.")
    else:
        print("SMOTE not requested or disabled; continuing without SMOTE.")

# ----- Train/test split (stratified) -----
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Train rows: {len(X_train)}, Test rows: {len(X_test)}")

# ----- Model training -----
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
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

model.fit(X_train, y_train)
print("Model training complete.")

# ----- Evaluation -----
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary', pos_label=1)

print(f"Accuracy: {acc:.4f}")
print(f"Precision (legit=1): {prec:.4f}, Recall (legit=1): {rec:.4f}, F1: {f1:.4f}")
print("\nClassification report:")
print(classification_report(y_test, y_pred, digits=4))

# Save model and feature order
joblib.dump(model, MODEL_PATH)
joblib.dump(FEATURE_COLUMNS, FEATURES_SAVE_PATH)
print(f"Saved model -> {MODEL_PATH}")
print(f"Saved feature order -> {FEATURES_SAVE_PATH}")

print("Training script finished.")
