import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
from urllib.parse import urlparse
import re

# --- Feature Extraction Functions ---
def get_url_length(url):
    return len(url)

def get_hostname_length(url):
    return len(urlparse(url).netloc)

def has_ip_address(url):
    # Use regex to check if the domain is an IP address
    return 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", urlparse(url).netloc) else 0

def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def count_at_symbol(url):
    return url.count('@')

# --- Main Training Logic ---
print("Starting model training...")

# Sample dataset (replace with a larger dataset for a real application)
# We've added a REAL, LIVE website to the phishing list for testing purposes
data = {
    'url': [
        'http://google.com',
        'http://youtube.com',
        'http://facebook.com',
        'http://wikipedia.org',
        'http://example.com', # ADDED FOR TESTING: A real site we'll pretend is phishing
        'http://my-secure-bank-login.com/update-info',
        'http://confirm-your-account-details.net/login.html',
        'http://192.168.1.1/admin',
        'http://paypal-support-team.com/verify'
    ],
    'label': [0, 0, 0, 0, 1, 1, 1, 1, 1]  # 0 for legitimate, 1 for phishing
}
df = pd.DataFrame(data)

# Feature Engineering
df['url_length'] = df['url'].apply(get_url_length)
df['hostname_length'] = df['url'].apply(get_hostname_length)
df['has_ip_address'] = df['url'].apply(has_ip_address)
df['num_dots'] = df['url'].apply(count_dots)
df['num_hyphens'] = df['url'].apply(count_hyphens)
# CORRECTED FEATURE NAME:
df['num_at'] = df['url'].apply(count_at_symbol)

# Define features (X) and target (y)
# CORRECTED FEATURE NAME IN LIST:
features_list = ['url_length', 'hostname_length', 'has_ip_address', 'num_dots', 'num_hyphens', 'num_at']
X = df[features_list]
y = df['label']

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and train the Random Forest model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
print("Model training complete.")

# Evaluate the model
y_pred = model.predict(X_test)
print(f"Model Accuracy: {accuracy_score(y_test, y_pred):.2f}")

# Save the trained model to a file
joblib.dump(model, 'phishguard_url_model.pkl')
print("Model saved successfully as phishguard_url_model.pkl")

