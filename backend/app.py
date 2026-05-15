"""
PhishCatcher Backend - Flask API with ML Model
Production-ready phishing detection system
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import numpy as np
import logging
from datetime import datetime
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for Chrome Extension

# Global variable for model
model = None
MODEL_PATH = 'phishing_model.pkl'

def load_model():
    """Load the trained model from disk"""
    global model
    try:
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, 'rb') as f:
                model = pickle.load(f)
            logger.info("Model loaded successfully")
            return True
        else:
            logger.error(f"Model file not found: {MODEL_PATH}")
            return False
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        return False

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/predict', methods=['POST'])
def predict():
    """
    Predict phishing probability for given features
    
    Expected input:
    {
        "features": [url_length, has_at, num_dots, is_https, ...]
    }
    
    Returns:
    {
        "probability": 0.85,
        "classification": "phishing",
        "confidence": "high",
        "timestamp": "2024-02-13T10:30:00"
    }
    """
    try:
        # Check if model is loaded
        if model is None:
            logger.error("Model not loaded")
            return jsonify({
                'error': 'Model not loaded. Please train the model first.'
            }), 500
        
        # Get JSON data
        data = request.get_json()
        
        if not data or 'features' not in data:
            return jsonify({
                'error': 'Invalid input. Expected {"features": [...]}'
            }), 400
        
        features = data['features']
        
        # Validate features
        if not isinstance(features, list) or len(features) != 15:
            return jsonify({
                'error': f'Expected 15 features, got {len(features) if isinstance(features, list) else 0}'
            }), 400
        
        # Convert to numpy array
        features_array = np.array(features).reshape(1, -1)
        
        # Make prediction
        probability = model.predict_proba(features_array)[0][1]  # Probability of phishing
        classification = "phishing" if probability > 0.6 else "legitimate"
        
        # Determine confidence level
        if probability > 0.8 or probability < 0.2:
            confidence = "high"
        elif probability > 0.65 or probability < 0.35:
            confidence = "medium"
        else:
            confidence = "low"
        
        result = {
            'probability': float(probability),
            'classification': classification,
            'confidence': confidence,
            'threshold': 0.6,
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"Prediction: {classification} (prob: {probability:.3f})")
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error during prediction: {str(e)}")
        return jsonify({
            'error': 'Internal server error during prediction',
            'details': str(e)
        }), 500

@app.route('/model/info', methods=['GET'])
def model_info():
    """Get information about the loaded model"""
    if model is None:
        return jsonify({'error': 'Model not loaded'}), 500
    
    return jsonify({
        'model_type': type(model).__name__,
        'features_count': 15,
        'threshold': 0.6,
        'status': 'ready'
    }), 200

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Load model on startup
    if load_model():
        logger.info("Starting PhishCatcher Backend...")
        app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        logger.error("Failed to load model. Please run train_model.py first.")
        print("\n⚠️  Model not found!")
        print("Please run: python train_model.py")
        print("This will train and save the model.\n")