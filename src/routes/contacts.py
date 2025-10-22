# routes/contacts.py
from flask import Blueprint, request, jsonify
from datetime import datetime
import uuid
import json
import os

contacts_bp = Blueprint('contacts', __name__)

# File paths
USERS_FILE = 'data/users.json'
CONTACTS_FILE = 'data/contacts.json'


def load_users():
    """Load users from JSON file"""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}


def load_contacts():
    """Load contacts from JSON file"""
    if os.path.exists(CONTACTS_FILE):
        with open(CONTACTS_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_contacts(contacts_data):
    """Save contacts to JSON file"""
    os.makedirs(os.path.dirname(CONTACTS_FILE), exist_ok=True)
    with open(CONTACTS_FILE, 'w') as f:
        json.dump(contacts_data, f, indent=2)


@contacts_bp.route('/contacts', methods=['GET'])
def get_contacts():
    """Get user's contact list"""
    user_id = request.args.get('user_id')

    if not user_id:
        return jsonify({"success": False, "error": "user_id parameter is required"}), 400

    # Load users to check if user exists
    users = load_users()
    if user_id not in users:
        return jsonify({"success": False, "error": "User not found"}), 404

    # Load contacts data
    contacts_data = load_contacts()

    # Get user's contacts or empty list if none
    user_contacts = contacts_data.get(user_id, [])

    # Get contact details from users database
    contacts_with_details = []
    for contact_username in user_contacts:
        if contact_username in users:
            contact_user = users[contact_username]
            contacts_with_details.append({
                "id": contact_username,
                "username": contact_username,
                "email": contact_user.get('email', ''),
                "is_online": contact_user.get('is_online', False),
                "last_seen": contact_user.get('last_seen', ''),
                "status": "online" if contact_user.get('is_online', False) else "offline"
            })

    return jsonify({
        "success": True,
        "contacts": contacts_with_details
    })


@contacts_bp.route('/search', methods=['GET'])
def search_contacts():
    """Search for users to add as contacts"""
    query = request.args.get('q', '').lower().strip()
    current_user_id = request.args.get('current_user_id')

    # Debug log
    print(f"DEBUG: Searching for '{query}' by user '{current_user_id}'")

    if not query or not current_user_id:
        return jsonify({"success": False, "error": "Missing search query or user_id"}), 400

    users = load_users()
    contacts_data = load_contacts()

    print(f"DEBUG: Total users in system: {len(users)}")  # Debug log
    print(f"DEBUG: Users found: {list(users.keys())}")    # Debug log

    # Get current user's existing contacts
    current_user_contacts = set(contacts_data.get(current_user_id, []))

    results = []
    for username, user_data in users.items():
        # Skip the current user themselves
        if username == current_user_id:
            continue

        # More flexible search - check if query is in username (case insensitive)
        if query in username.lower():
            print(f"DEBUG: Found match - {username}")  # Debug log
            results.append({
                "id": username,
                "username": username,
                "email": user_data.get('email', ''),
                "is_contact": username in current_user_contacts,
                "has_pending_request": False,
                "is_online": user_data.get('is_online', False),
                "status": "online" if user_data.get('is_online', False) else "offline"
            })

    print(f"DEBUG: Search results: {len(results)}")  # Debug log

    return jsonify({
        "success": True,
        "results": results
    })


@contacts_bp.route('/request', methods=['POST'])
def send_contact_request():
    """Send a contact request to another user"""
    data = request.get_json()
    from_user_id = data.get('from_user_id')
    to_user_id = data.get('to_user_id')

    if not from_user_id or not to_user_id:
        return jsonify({"success": False, "error": "Missing user IDs"}), 400

    users = load_users()
    if from_user_id not in users or to_user_id not in users:
        return jsonify({"success": False, "error": "User not found"}), 404

    # Load and update contacts
    contacts_data = load_contacts()

    # Initialize user's contact list if not exists
    if from_user_id not in contacts_data:
        contacts_data[from_user_id] = []
    if to_user_id not in contacts_data:
        contacts_data[to_user_id] = []

    # Check if already contacts
    if to_user_id in contacts_data[from_user_id]:
        return jsonify({"success": False, "error": "User is already in your contacts"}), 400

    # Add to contacts (simplified - in real app you'd have pending requests)
    contacts_data[from_user_id].append(to_user_id)
    contacts_data[to_user_id].append(from_user_id)

    # Save updated contacts
    save_contacts(contacts_data)

    return jsonify({
        "success": True,
        "message": "Contact added successfully"
    })


@contacts_bp.route('/request/<request_id>', methods=['POST'])
def respond_contact_request(request_id):
    """Accept or reject a contact request"""
    # For now, return a simple response since we simplified the contact system
    return jsonify({
        "success": True,
        "message": "Contact system simplified - requests auto-accepted"
    })


@contacts_bp.route('/debug/users', methods=['GET'])
def debug_users():
    """Debug endpoint to see all users in the system"""
    users = load_users()

    user_list = []
    for username, user_data in users.items():
        user_list.append({
            "username": username,
            "email": user_data.get('email', ''),
            "is_online": user_data.get('is_online', False)
        })

    return jsonify({
        "success": True,
        "total_users": len(user_list),
        "users": user_list
    })


@contacts_bp.route('/test', methods=['GET'])
def test_route():
    """Test endpoint to verify contacts routes are working"""
    return jsonify({
        "success": True,
        "message": "Contacts routes are working!",
        "endpoint": "/api/contacts/test"
    })
