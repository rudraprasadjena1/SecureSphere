# src/routes/matrix_simple.py
from flask import Blueprint, request, jsonify, current_app
from src.middleware.auth import token_required
from src.services.matrix_service import SimpleMatrixService
import json

matrix_bp = Blueprint('matrix', __name__)

# Store Matrix sessions (in production, use Redis/database)
matrix_sessions = {}

def get_matrix_service(user_id):
    """Get or create Matrix service for user"""
    if user_id not in matrix_sessions:
        matrix_sessions[user_id] = SimpleMatrixService()
    return matrix_sessions[user_id]

@matrix_bp.route("/matrix/login", methods=["POST"])
@token_required
def matrix_login():
    """Connect to Matrix account"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    matrix_username = data.get("matrix_username")
    matrix_password = data.get("matrix_password")
    
    if not matrix_username or not matrix_password:
        return jsonify({"error": "Matrix username and password required"}), 400
    
    service = get_matrix_service(request.username)
    success = service.login(matrix_username, matrix_password)
    
    if success:
        return jsonify({
            "success": True,
            "message": "Connected to Matrix successfully",
            "username": matrix_username
        })
    else:
        return jsonify({"error": "Failed to connect to Matrix"}), 400

@matrix_bp.route("/matrix/rooms", methods=["GET"])
@token_required
def get_matrix_rooms():
    """Get user's Matrix rooms"""
    service = get_matrix_service(request.username)
    rooms = service.get_rooms()
    
    return jsonify({
        "success": True,
        "rooms": rooms
    })

@matrix_bp.route("/matrix/send", methods=["POST"])
@token_required
def send_matrix_message():
    """Send message to Matrix room"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    room_id = data.get("room_id")
    message = data.get("message")
    
    if not room_id or not message:
        return jsonify({"error": "Room ID and message required"}), 400
    
    service = get_matrix_service(request.username)
    success = service.send_message(room_id, message)
    
    if success:
        return jsonify({
            "success": True,
            "message": "Message sent to Matrix"
        })
    else:
        return jsonify({"error": "Failed to send message to Matrix"}), 500

@matrix_bp.route("/matrix/status", methods=["GET"])
@token_required
def matrix_status():
    """Check Matrix connection status"""
    service = get_matrix_service(request.username)
    is_connected = service.access_token is not None
    
    return jsonify({
        "connected": is_connected,
        "homeserver": current_app.config.get('MATRIX_HOMESERVER_URL', 'https://matrix.org')
    })