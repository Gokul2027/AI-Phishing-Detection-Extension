from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import joblib
import re
from urllib.parse import urlparse

# --- Feature Extraction Functions ---
# These functions must be IDENTICAL to the ones in your training script.
def get_url_length(url):
    return len(url)

def get_hostname_length(url):
    return len(urlparse(url).netloc)

def has_ip_address(url):
    # This regex is simplified for this example
    return 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", urlparse(url).netloc) else 0

def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def count_at_symbol(url):
    return url.count('@')

# --- Main Feature Extraction Wrapper ---
def extract_features(url):
    # Create a dictionary of features
    features = {
        'url_length': get_url_length(url),
        'hostname_length': get_hostname_length(url),
        'has_ip_address': has_ip_address(url),
        'num_dots': count_dots(url),
        'num_hyphens': count_hyphens(url),
        'num_at': count_at_symbol(url)
    }
    # Convert the dictionary to a pandas DataFrame
    # The columns must be in the same order as they were during training
    return pd.DataFrame([features], columns=['url_length', 'hostname_length', 'has_ip_address', 'num_dots', 'num_hyphens', 'num_at'])


# --- Flask Application Setup ---
app = Flask(__name__)
CORS(app) # Enable Cross-Origin Resource Sharing

# Load the trained machine learning model from the file
try:
    model = joblib.load('phishguard_url_model.pkl')
    print("Model loaded successfully.")
except FileNotFoundError:
    print("Error: Model file 'phishguard_url_model.pkl' not found.")
    print("Please run the 'url_model_trainer.py' script first.")
    exit()


@app.route('/analyze', methods=['POST'])
def analyze():
    # Get the JSON data sent from the Chrome extension
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL not provided"}), 400

    url_to_check = data['url']
    
    # Extract features from the URL
    features_df = extract_features(url_to_check)
    
    # Use the loaded model to make a prediction
    prediction = model.predict(features_df)
    
    # The prediction will be 0 (safe) or 1 (phishing)
    is_phishing = bool(prediction[0])
    
    # Send the result back to the Chrome extension
    return jsonify({'is_phishing': is_phishing})


if __name__ == '__main__':
    # Run the Flask app on the local server
    app.run(host='127.0.0.1', port=5000, debug=True)

