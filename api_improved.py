from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import pickle
import os

# Import detector
from working_phishing_detector import detector

app = Flask(__name__)
CORS(app)

# ---------- LOAD MODEL CORRECTLY FOR RENDER ----------
def load_model():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(base_dir, 'svm_phishing_model.pkl')

        print(f"Looking for model at: {model_path}")

        with open(model_path, 'rb') as f:
            detector.pipeline = pickle.load(f)

        detector.is_trained = True
        print("✅ Model loaded successfully!")
        return True

    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return False

model_loaded = load_model()
# -----------------------------------------------------

@app.route('/')
def serve_index():
    return send_from_directory('.', 'login.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/api/health')
def health():
    return jsonify({
        "status": "running",
        "model_loaded": model_loaded
    })

@app.route('/api/predict', methods=['POST'])
def predict():
    if not model_loaded:
        return jsonify({"error": "Model not loaded"}), 500

    data = request.get_json()
    email_text = data.get("email_text", "")

    result = detector.predict_email(email_text)
    explanation = detector.generate_detailed_explanation(email_text)

    return jsonify({
        "prediction": result,
        "explanation": explanation
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
