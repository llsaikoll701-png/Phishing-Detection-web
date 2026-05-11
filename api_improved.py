"""
Improved Phishing Detection Flask API
AI-Driven Awareness Program for Phishing Email Detection using SVM
Author: MiniMax Agent
Python Version: 3.13.4
Minimum Supported: Python 3.7.3
Created: 2026-05-11
Enhanced Version with improved model accuracy
"""



from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import pickle
import sys
import os

# Import our phishing detector
from working_phishing_detector import detector

# Version Information
PYTHON_VERSION = "3.13.4"
MIN_PYTHON_VERSION = "3.7.3"
API_VERSION = "1.0"

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load the trained model
def load_model():
    try:
        with open('svm_phishing_model.pkl', 'rb') as f:
            detector.pipeline = pickle.load(f)
        detector.is_trained = True
        print("Model loaded successfully!")
        return True
    except Exception as e:
        print(f"Error loading model: {e}")
        return False

# Load model on startup
model_loaded = load_model()

@app.route('/')
def serve_index():
    """Serve the main HTML page"""
    return send_from_directory('.', 'login.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files (CSS, JS, etc.)"""
    return send_from_directory('.', path)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model_loaded,
        'message': 'Phishing Detection API is running',
        'version_info': {
            'api_version': API_VERSION,
            'python_version': PYTHON_VERSION,
            'minimum_python': MIN_PYTHON_VERSION
        }
    })

@app.route('/api/predict', methods=['POST'])
def predict_email():
    """Predict if an email is phishing or safe"""
    try:
        if not model_loaded:
            return jsonify({
                'error': 'Model not loaded',
                'status': 'error'
            }), 500
        
        # Get email text from request
        data = request.get_json()
        if not data or 'email_text' not in data:
            return jsonify({
                'error': 'Missing email_text in request',
                'status': 'error'
            }), 400
        
        email_text = data['email_text']
        if not email_text or email_text.strip() == '':
            return jsonify({
                'error': 'Email text cannot be empty',
                'status': 'error'
            }), 400
        
        # Make prediction
        result = detector.predict_email(email_text)
        explanation = detector.generate_detailed_explanation(email_text)
        
        return jsonify({
            'status': 'success',
            'prediction': result,
            'explanation': explanation
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/explain', methods=['POST'])
def explain_prediction():
    """Get detailed explanation for email classification"""
    try:
        if not model_loaded:
            return jsonify({
                'error': 'Model not loaded',
                'status': 'error'
            }), 500
        
        # Get email text from request
        data = request.get_json()
        if not data or 'email_text' not in data:
            return jsonify({
                'error': 'Missing email_text in request',
                'status': 'error'
            }), 400
        
        email_text = data['email_text']
        if not email_text or email_text.strip() == '':
            return jsonify({
                'error': 'Email text cannot be empty',
                'status': 'error'
            }), 400
        
        # Generate explanation
        explanation = detector.generate_detailed_explanation(email_text)
        
        return jsonify({
            'status': 'success',
            'explanation': explanation
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/model-info', methods=['GET'])
def model_info():
    """Get information about the trained model"""
    try:
        if not model_loaded:
            return jsonify({
                'error': 'Model not loaded',
                'status': 'error'
            }), 500
        
        return jsonify({
            'status': 'success',
            'model_type': 'Support Vector Machine (SVM)',
            'algorithm': 'Linear SVM with TF-IDF Vectorization',
            'training_method': 'Sample dataset with phishing and safe emails',
            'features': 'TF-IDF vectorization of email text',
            'description': 'AI-Driven Awareness Program for Phishing Email Detection using SVM',
            'version_info': {
                'python_version': PYTHON_VERSION,
                'minimum_python': MIN_PYTHON_VERSION,
                'api_version': API_VERSION
            }
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'status': 'error'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'status': 'error'
    }), 500

if __name__ == '__main__':
    print("=== Phishing Detection API ===")
    print(f"Python Version: {PYTHON_VERSION}")
    print(f"Minimum Supported: {MIN_PYTHON_VERSION}")
    print(f"API Version: {API_VERSION}")
    print("="*40)
    print("Starting Phishing Detection API...")
    print(f"Model loaded: {model_loaded}")
    
    if model_loaded:
        print("API is ready to accept requests!")
        print("Endpoints:")
        print("  GET  /api/health - Health check")
        print("  GET  /api/model-info - Model information")
        print("  POST /api/predict - Predict email classification")
        print("  POST /api/explain - Get detailed explanation")
    
    # Run the Flask app
    app.run(debug=False, host='0.0.0.0', port=10000)
