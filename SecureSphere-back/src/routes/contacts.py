# src\routes\contacts.py
from flask import Blueprint, request, jsonify, current_app
from src.models.user import UserManager
from src.models.contact_request_manager import ContactRequestManager

contacts_bp = Blueprint('contacts', __name__)

def get_user_manager():
    return UserManager(current_app.config.get('USERS_FILE', 'data/users.json'))

def get_contact_request_manager():
    return ContactRequestManager(current_app.config.get('CONTACT_REQUESTS_FILE', 'data/contact_requests.json'))

@contacts_bp.route("/request", methods=["POST"])
def request_contact():
    data = request.get_json()
    if not data or "from_user" not in data or "to_user" not in data:
        return jsonify({"error": "Request requires 'from_user' and 'to_user'"}), 400

    from_user_id = data.get("from_user")
    to_user_id = data.get("to_user")
    message = data.get("message", "")

    user_manager = get_user_manager()
    if not user_manager.get_user(from_user_id) or not user_manager.get_user(to_user_id):
        return jsonify({"error": "One or more users not found"}), 404

    request_manager = get_contact_request_manager()
    new_request = request_manager.create_request(from_user_id, to_user_id, message)

    if new_request is None:
        return jsonify({"error": "A pending contact request already exists between these users."}), 409
    # For simplicity, auto-accept the request in this example
    request_manager.update_request_status(new_request['id'], "accepted")
    user_manager.add_contact(from_user_id, to_user_id)
    
    return jsonify({"success": True, "message": "Contact request sent.", "request": new_request})

@contacts_bp.route("/accept", methods=["POST"])
def accept_contact_request():
    data = request.get_json()
    if not data or "request_id" not in data or "user_id" not in data:
        return jsonify({"error": "Request requires 'request_id' and 'user_id' (the acceptor)"}), 400

    request_id = data.get("request_id")
    accepting_user_id = data.get("user_id")

    request_manager = get_contact_request_manager()
    contact_request = request_manager.get_request(request_id)

    if not contact_request or contact_request['to_user_id'] != accepting_user_id:
        return jsonify({"error": "Request not found or you are not authorized to accept it."}), 404

    # Update request status to 'accepted'
    request_manager.update_request_status(request_id, "accepted")

    # Add users to each other's contact lists
    user_manager = get_user_manager()
    from_user_id = contact_request['from_user_id']
    to_user_id = contact_request['to_user_id']
    user_manager.add_contact(from_user_id, to_user_id)
    # The add_contact method in user.py should already handle the reciprocal relationship

    return jsonify({"success": True, "message": "Contact request accepted."})

@contacts_bp.route("/contacts", methods=["GET"])
def get_contacts():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id parameter is required"}), 400

    user_manager = get_user_manager()
    user = user_manager.get_user(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Get established contacts
    contact_list = []
    for contact_username in user.contacts:
        contact_user = user_manager.get_user(contact_username)
        if contact_user:
            response = contact_user.dict()
            response['status'] = 'accepted'
            contact_list.append(response)
    
    return jsonify({"success": True, "contacts": contact_list})

@contacts_bp.route("/search", methods=["GET"])
def search_users():
    query = request.args.get('q', '').lower()
    current_user_id = request.args.get('current_user_id')
    if not query or not current_user_id:
        return jsonify({"success": True, "results": []})

    user_manager = get_user_manager()
    request_manager = get_contact_request_manager()
    all_users = user_manager.get_all_users()
    current_user = user_manager.get_user(current_user_id)

    results = []
    for user in all_users:
        if query in user.username.lower() and user.username != current_user_id:
            response = user.dict()
            # Determine contact status
            if user.username in current_user.contacts:
                response['status'] = 'accepted'
            else:
                existing_request = request_manager.get_request_between_users(current_user_id, user.username)
                if existing_request:
                    response['status'] = existing_request['status'] # 'pending' or 'rejected'
                else:
                    response['status'] = 'not_contact'
            results.append(response)

    return jsonify({"success": True, "results": results})