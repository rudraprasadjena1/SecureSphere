# app.py
import os
import sys

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from flask import Flask, jsonify, g
from flask_cors import CORS
from config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize extensions
    CORS(app)
    
    # Import and register blueprints
    try:
        from src.routes.auth import auth_bp
        from src.routes.message import message_bp
        
        # Register blueprints
        app.register_blueprint(auth_bp, url_prefix='/api/auth')
        app.register_blueprint(message_bp, url_prefix='/api/message')
        
        print("Successfully registered auth and message blueprints")
        
    except ImportError as e:
        print(f"Warning: Could not import blueprints: {e}")
    
    # Root endpoint
    @app.route("/")
    def index():
        return "Quantum-Safe Communication (Kyber + Dilithium + AES-GCM)"
    
    # Health check endpoint
    @app.route("/health")
    def health():
        return jsonify({"status": "healthy", "service": "quantum-safe-chat"})
    
    return app

if __name__ == "__main__":
    app = create_app()
    print("Starting Quantum-Safe Chat Server...")
    app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=5000)