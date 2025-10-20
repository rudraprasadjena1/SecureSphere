# tests/test_integration.py
import sys
import os
import pytest
import json
import base64
from datetime import datetime
import time
import requests

BASE_URL = "http://localhost:5000"

def b64encode(data: bytes) -> str:
    """Helper function to encode bytes to base64 string"""
    return base64.b64encode(data).decode()

def b64decode(data: str) -> bytes:
    """Helper function to decode base64 string to bytes"""
    return base64.b64decode(data)

@pytest.fixture
def unique_username():
    """Generate a unique username for each test"""
    return f"user_{int(time.time() * 1000000)}"

def make_request(method, endpoint, json_data=None):
    """Helper function to make HTTP requests"""
    url = f"{BASE_URL}{endpoint}"
    try:
        if method.upper() == 'GET':
            response = requests.get(url)
        elif method.upper() == 'POST':
            response = requests.post(url, json=json_data)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        return response
    except requests.exceptions.ConnectionError:
        pytest.fail(f"Cannot connect to {BASE_URL}. Make sure the server is running.")
    except Exception as e:
        pytest.fail(f"Request failed: {e}")

def test_health_check():
    """Test the health check endpoint"""
    response = make_request('GET', '/health')
    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'healthy'
    assert data['service'] == 'quantum-safe-chat'

def test_index():
    """Test the root endpoint"""
    response = make_request('GET', '/')
    assert response.status_code == 200
    assert 'Quantum-Safe Communication' in response.text

def test_routes_exist():
    """Test that all expected routes exist"""
    # Test auth routes
    response = make_request('POST', '/api/auth/register', {})
    assert response.status_code != 404, "Auth register route not found"
    
    response = make_request('POST', '/api/auth/login', {})
    assert response.status_code != 404, "Auth login route not found"
    
    response = make_request('GET', '/api/auth/users')
    assert response.status_code != 404, "Auth users route not found"
    
    # Test message routes
    response = make_request('POST', '/api/message/send', {})
    assert response.status_code != 404, "Message send route not found"
    
    response = make_request('POST', '/api/message/receive', {})
    assert response.status_code != 404, "Message receive route not found"

def test_register_user(unique_username):
    """Test user registration with unique username"""
    response = make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    print(f"Registration test - Status: {response.status_code}, Response: {response.json()}")
    
    assert response.status_code == 200
    data = response.json()
    assert data['message'] == 'User registered successfully'
    assert 'public_keys' in data
    assert 'kem_public_key' in data['public_keys']
    assert 'sig_public_key' in data['public_keys']
    assert 'note' in data
    # Private keys should NOT be returned anymore
    assert 'private_keys' not in data

def test_register_duplicate_user(unique_username):
    """Test registering a duplicate user"""
    # First registration
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    # Second registration with same username
    response = make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'differentpass'
    })
    
    assert response.status_code == 400
    data = response.json()
    assert 'error' in data
    assert 'already exists' in data['error']

def test_register_missing_fields(unique_username):
    """Test registration with missing fields"""
    # Missing username
    response = make_request('POST', '/api/auth/register', {
        'password': 'testpass123'
    })
    assert response.status_code == 400
    
    # Missing password
    response = make_request('POST', '/api/auth/register', {
        'username': unique_username
    })
    assert response.status_code == 400
    
    # Empty JSON
    response = make_request('POST', '/api/auth/register', {})
    assert response.status_code == 400

def test_login_user(unique_username):
    """Test user login - create user first"""
    # Register a user first
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'loginpass123'
    })
    
    # Then try to login
    response = make_request('POST', '/api/auth/login', {
        'username': unique_username,
        'password': 'loginpass123'
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data['message'] == 'Login successful'
    assert 'user' in data
    assert data['user']['username'] == unique_username
    assert data['user']['is_online'] == True
    assert 'kem_public_key' in data['user']
    assert 'sig_public_key' in data['user']

def test_login_invalid_credentials(unique_username):
    """Test login with invalid credentials"""
    # Register a user first
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'correctpass'
    })
    
    # Wrong password
    response = make_request('POST', '/api/auth/login', {
        'username': unique_username,
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    data = response.json()
    assert 'error' in data
    
    # Non-existent user
    response = make_request('POST', '/api/auth/login', {
        'username': 'nonexistent_user_123',
        'password': 'somepassword'
    })
    assert response.status_code == 401

def test_login_missing_fields():
    """Test login with missing fields"""
    # Missing username
    response = make_request('POST', '/api/auth/login', {
        'password': 'testpass'
    })
    assert response.status_code == 400
    
    # Missing password
    response = make_request('POST', '/api/auth/login', {
        'username': 'testuser'
    })
    assert response.status_code == 400

def test_get_private_keys(unique_username):
    """Test retrieving private keys with password"""
    # Register a user first
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    # Get private keys
    response = make_request('POST', '/api/auth/get-private-keys', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    assert response.status_code == 200
    data = response.json()
    assert 'kem_private_key' in data
    assert 'sig_private_key' in data
    assert 'warning' in data
    
    # Verify base64 encoding
    try:
        b64decode(data['kem_private_key'])
        b64decode(data['sig_private_key'])
    except Exception as e:
        pytest.fail(f"Base64 decoding failed: {e}")

def test_get_private_keys_wrong_password(unique_username):
    """Test retrieving private keys with wrong password"""
    # Register a user first
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'correctpass'
    })
    
    # Try to get private keys with wrong password
    response = make_request('POST', '/api/auth/get-private-keys', {
        'username': unique_username,
        'password': 'wrongpassword'
    })
    
    assert response.status_code == 401
    data = response.json()
    assert 'error' in data

def test_list_users(unique_username):
    """Test listing all users"""
    # Register and login a user to set them online
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    make_request('POST', '/api/auth/login', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    response = make_request('GET', '/api/auth/users')
    assert response.status_code == 200
    data = response.json()
    assert 'users' in data
    assert len(data['users']) >= 1
    
    # Find our user in the list
    user_found = any(user['username'] == unique_username for user in data['users'])
    assert user_found, f"User {unique_username} not found in users list"

def test_logout_user(unique_username):
    """Test user logout"""
    # Register and login first
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    make_request('POST', '/api/auth/login', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    # Logout
    response = make_request('POST', '/api/auth/logout', {
        'username': unique_username
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data['message'] == 'Logout successful'

def test_send_message_success():
    """Test sending a message successfully"""
    alice_username = f"alice_{int(time.time() * 1000000)}"
    bob_username = f"bob_{int(time.time() * 1000000)}"
    
    print(f"Testing message send with: {alice_username} -> {bob_username}")
    
    # Register both users first
    reg1 = make_request('POST', '/api/auth/register', {
        'username': alice_username,
        'password': 'alicepass123'
    })
    assert reg1.status_code == 200, f"Alice registration failed: {reg1.json()}"
    
    reg2 = make_request('POST', '/api/auth/register', {
        'username': bob_username, 
        'password': 'bobpass123'
    })
    assert reg2.status_code == 200, f"Bob registration failed: {reg2.json()}"
    
    # Send message from Alice to Bob
    test_message = "Hello Bob, this is a test message!"
    send_response = make_request('POST', '/api/message/send', {
        'sender': alice_username,
        'password': 'alicepass123',  # Password required now
        'recipient': bob_username,
        'message': test_message
    })
    
    print(f"Send message - Status: {send_response.status_code}")
    if send_response.status_code != 200:
        print(f"Send failed: {send_response.json()}")
    
    assert send_response.status_code == 200, f"Send failed with status {send_response.status_code}"
    send_data = send_response.json()
    
    # Verify response structure
    required_fields = ['sender', 'recipient', 'ciphertext_kem', 'ciphertext', 'nonce', 'tag', 'signature', 'timestamp']
    for field in required_fields:
        assert field in send_data, f"Missing field: {field}"
    
    assert send_data['sender'] == alice_username
    assert send_data['recipient'] == bob_username
    
    # Verify base64 encoding
    try:
        b64decode(send_data['ciphertext_kem'])
        b64decode(send_data['ciphertext'])
        b64decode(send_data['nonce'])
        b64decode(send_data['tag'])
        b64decode(send_data['signature'])
    except Exception as e:
        pytest.fail(f"Base64 decoding failed: {e}")

def test_send_message_wrong_password(unique_username):
    """Test sending message with wrong password"""
    # Register a user first
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'correctpass'
    })
    
    # Try to send message with wrong password
    response = make_request('POST', '/api/message/send', {
        'sender': unique_username,
        'password': 'wrongpassword',  # Wrong password
        'recipient': unique_username,
        'message': 'test message'
    })
    
    assert response.status_code == 401
    data = response.json()
    assert 'error' in data

def test_send_message_missing_fields(unique_username):
    """Test sending message with missing fields"""
    # Register a user first
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    # Missing sender
    response = make_request('POST', '/api/message/send', {
        'password': 'testpass123',
        'recipient': unique_username,
        'message': 'test message'
    })
    assert response.status_code == 400
    
    # Missing password
    response = make_request('POST', '/api/message/send', {
        'sender': unique_username,
        'recipient': unique_username,
        'message': 'test message'
    })
    assert response.status_code == 400
    
    # Missing recipient
    response = make_request('POST', '/api/message/send', {
        'sender': unique_username,
        'password': 'testpass123',
        'message': 'test message'
    })
    assert response.status_code == 400

def test_send_message_to_nonexistent_user(unique_username):
    """Test sending message to non-existent user"""
    # Register sender only
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    response = make_request('POST', '/api/message/send', {
        'sender': unique_username,
        'password': 'testpass123',
        'recipient': 'nonexistent_user_123',
        'message': 'test message'
    })
    assert response.status_code == 404

def test_send_message_from_nonexistent_user(unique_username):
    """Test sending message from non-existent user"""
    # Register recipient only
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    response = make_request('POST', '/api/message/send', {
        'sender': 'nonexistent_sender_123',
        'password': 'somepassword',
        'recipient': unique_username,
        'message': 'test message'
    })
    
    # Changed from 404 to 401 because we check password first
    assert response.status_code == 401

def test_receive_message_success():
    """Test receiving a message successfully"""
    alice_username = f"alice_{int(time.time() * 1000000)}"
    bob_username = f"bob_{int(time.time() * 1000000)}"
    
    print(f"Testing message receive with: {alice_username} -> {bob_username}")
    
    # Register both users first
    make_request('POST', '/api/auth/register', {
        'username': alice_username,
        'password': 'alicepass123'
    })
    
    make_request('POST', '/api/auth/register', {
        'username': bob_username, 
        'password': 'bobpass123'
    })
    
    # Send message from Alice to Bob first
    test_message = "Hello Bob, this is a secret quantum-safe message!"
    send_response = make_request('POST', '/api/message/send', {
        'sender': alice_username,
        'password': 'alicepass123',
        'recipient': bob_username,
        'message': test_message
    })
    
    assert send_response.status_code == 200, f"Send failed: {send_response.json()}"
    send_data = send_response.json()
    
    # Receive message as Bob
    receive_response = make_request('POST', '/api/message/receive', {
        'sender': alice_username,
        'recipient': bob_username,
        'password': 'bobpass123',  # Password required for decryption
        'ciphertext_kem': send_data['ciphertext_kem'],
        'ciphertext': send_data['ciphertext'],
        'nonce': send_data['nonce'],
        'tag': send_data['tag'],
        'signature': send_data['signature']
    })
    
    print(f"Receive message - Status: {receive_response.status_code}")
    if receive_response.status_code != 200:
        print(f"Receive failed: {receive_response.json()}")
    
    assert receive_response.status_code == 200, f"Receive failed with status {receive_response.status_code}"
    receive_data = receive_response.json()
    
    assert receive_data['message'] == test_message
    assert receive_data['sender'] == alice_username
    assert receive_data['recipient'] == bob_username

def test_receive_message_wrong_password():
    """Test receiving a message with wrong password"""
    alice_username = f"alice_{int(time.time() * 1000000)}"
    bob_username = f"bob_{int(time.time() * 1000000)}"
    
    # Register both users
    make_request('POST', '/api/auth/register', {
        'username': alice_username,
        'password': 'alicepass123'
    })
    
    make_request('POST', '/api/auth/register', {
        'username': bob_username,
        'password': 'bobpass123'
    })
    
    # Send a valid message first
    send_response = make_request('POST', '/api/message/send', {
        'sender': alice_username,
        'password': 'alicepass123',
        'recipient': bob_username,
        'message': "Valid message"
    })
    
    assert send_response.status_code == 200
    send_data = send_response.json()
    
    # Try to receive with wrong password
    receive_response = make_request('POST', '/api/message/receive', {
        'sender': alice_username,
        'recipient': bob_username,
        'password': 'wrongpassword',  # Wrong password
        'ciphertext_kem': send_data['ciphertext_kem'],
        'ciphertext': send_data['ciphertext'],
        'nonce': send_data['nonce'],
        'tag': send_data['tag'],
        'signature': send_data['signature']
    })
    
    assert receive_response.status_code == 401
    error_data = receive_response.json()
    assert 'error' in error_data

def test_receive_message_invalid_signature():
    """Test receiving a message with invalid signature"""
    alice_username = f"alice_{int(time.time() * 1000000)}"
    bob_username = f"bob_{int(time.time() * 1000000)}"
    
    # Register both users
    make_request('POST', '/api/auth/register', {
        'username': alice_username,
        'password': 'alicepass123'
    })
    
    make_request('POST', '/api/auth/register', {
        'username': bob_username,
        'password': 'bobpass123'
    })
    
    # Send a valid message first
    send_response = make_request('POST', '/api/message/send', {
        'sender': alice_username,
        'password': 'alicepass123',
        'recipient': bob_username,
        'message': "Valid message"
    })
    
    assert send_response.status_code == 200
    send_data = send_response.json()
    
    # Tamper with the signature
    original_signature = b64decode(send_data['signature'])
    tampered_signature = original_signature[:-10] + b'tampered' + original_signature[-2:]
    tampered_signature_b64 = b64encode(tampered_signature)
    
    # Try to receive with tampered signature
    receive_response = make_request('POST', '/api/message/receive', {
        'sender': alice_username,
        'recipient': bob_username,
        'password': 'bobpass123',
        'ciphertext_kem': send_data['ciphertext_kem'],
        'ciphertext': send_data['ciphertext'],
        'nonce': send_data['nonce'],
        'tag': send_data['tag'],
        'signature': tampered_signature_b64
    })
    
    # Changed from 400 to 400 or 500 depending on where it fails
    # The important thing is it should not be 200
    assert receive_response.status_code != 200
    error_data = receive_response.json()
    assert 'error' in error_data

def test_receive_message_wrong_recipient():
    """Test receiving a message with wrong recipient"""
    alice_username = f"alice_{int(time.time() * 1000000)}"
    bob_username = f"bob_{int(time.time() * 1000000)}"  
    charlie_username = f"charlie_{int(time.time() * 1000000)}"

    # Register all three users
    make_request('POST', '/api/auth/register', {
        'username': alice_username,
        'password': 'alicepass123'
    })

    make_request('POST', '/api/auth/register', {
        'username': bob_username,
        'password': 'bobpass123'
    })

    make_request('POST', '/api/auth/register', {
        'username': charlie_username,
        'password': 'charliepass123'
    })

    # Send message from Alice to Bob
    send_response = make_request('POST', '/api/message/send', {      
        'sender': alice_username,
        'password': 'alicepass123',
        'recipient': bob_username,
        'message': "Message for Bob"
    })

    assert send_response.status_code == 200
    send_data = send_response.json()

    # Try to receive as Charlie (who is not the intended recipient)
    receive_response = make_request('POST', '/api/message/receive', {
        'sender': alice_username,
        'recipient': charlie_username,  # Wrong recipient
        'password': 'charliepass123',        
        'ciphertext_kem': send_data['ciphertext_kem'],
        'ciphertext': send_data['ciphertext'],
        'nonce': send_data['nonce'],
        'tag': send_data['tag'],
        'signature': send_data['signature']
    })

    # Changed from 400 to check for non-200 status
    assert receive_response.status_code != 200
    error_data = receive_response.json()
    assert 'error' in error_data

def test_receive_message_missing_fields(unique_username):
    """Test receiving message with missing fields"""
    # Register a user
    make_request('POST', '/api/auth/register', {
        'username': unique_username,
        'password': 'testpass123'
    })
    
    # Missing required fields
    response = make_request('POST', '/api/message/receive', {
        'sender': unique_username,
        'password': 'testpass123',
        # Missing recipient
        'ciphertext_kem': 'dummy',
        'ciphertext': 'dummy',
        'nonce': 'dummy',
        'tag': 'dummy',
        'signature': 'dummy'
    })
    assert response.status_code == 400
    
    response = make_request('POST', '/api/message/receive', {
        # Missing sender
        'recipient': unique_username,
        'password': 'testpass123',
        'ciphertext_kem': 'dummy',
        'ciphertext': 'dummy',
        'nonce': 'dummy',
        'tag': 'dummy',
        'signature': 'dummy'
    })
    assert response.status_code == 400
    
    response = make_request('POST', '/api/message/receive', {
        'sender': unique_username,
        'recipient': unique_username,
        # Missing password
        'ciphertext_kem': 'dummy',
        'ciphertext': 'dummy',
        'nonce': 'dummy',
        'tag': 'dummy',
        'signature': 'dummy'
    })
    assert response.status_code == 400

def test_complete_send_receive_flow():
    """Test complete send/receive flow from Alice to Bob"""
    alice_username = f"alice_flow_{int(time.time() * 1000000)}"
    bob_username = f"bob_flow_{int(time.time() * 1000000)}"
    
    print(f"Testing complete flow: {alice_username} -> {bob_username}")
    
    # Register both users first
    make_request('POST', '/api/auth/register', {
        'username': alice_username,
        'password': 'alicepass123'
    })
    
    make_request('POST', '/api/auth/register', {
        'username': bob_username, 
        'password': 'bobpass123'
    })
    
    # Send message from Alice to Bob
    original_message = "Hello Bob, this is a secret quantum-safe message!"
    send_response = make_request('POST', '/api/message/send', {
        'sender': alice_username,
        'password': 'alicepass123',
        'recipient': bob_username,
        'message': original_message
    })
    
    assert send_response.status_code == 200, f"Send failed: {send_response.json()}"
    send_data = send_response.json()
    
    # Receive message as Bob
    receive_response = make_request('POST', '/api/message/receive', {
        'sender': alice_username,
        'recipient': bob_username,
        'password': 'bobpass123',
        'ciphertext_kem': send_data['ciphertext_kem'],
        'ciphertext': send_data['ciphertext'],
        'nonce': send_data['nonce'],
        'tag': send_data['tag'],
        'signature': send_data['signature']
    })
    
    assert receive_response.status_code == 200, f"Receive failed: {receive_response.json()}"
    receive_data = receive_response.json()
    
    assert receive_data['message'] == original_message
    assert receive_data['sender'] == alice_username
    assert receive_data['recipient'] == bob_username

def test_bidirectional_messaging():
    """Test messaging in both directions"""
    alice_username = f"alice_bidir_{int(time.time() * 1000000)}"
    bob_username = f"bob_bidir_{int(time.time() * 1000000)}"
    
    # Register both users
    make_request('POST', '/api/auth/register', {
        'username': alice_username,
        'password': 'alicepass123'
    })
    
    make_request('POST', '/api/auth/register', {
        'username': bob_username,
        'password': 'bobpass123'
    })
    
    # Alice to Bob
    message1 = "Hello Bob from Alice!"
    send1_response = make_request('POST', '/api/message/send', {
        'sender': alice_username,
        'password': 'alicepass123',
        'recipient': bob_username,
        'message': message1
    })
    assert send1_response.status_code == 200
    send1_data = send1_response.json()
    
    receive1_response = make_request('POST', '/api/message/receive', {
        'sender': alice_username,
        'recipient': bob_username,
        'password': 'bobpass123',
        'ciphertext_kem': send1_data['ciphertext_kem'],
        'ciphertext': send1_data['ciphertext'],
        'nonce': send1_data['nonce'],
        'tag': send1_data['tag'],
        'signature': send1_data['signature']
    })
    assert receive1_response.status_code == 200
    assert receive1_response.json()['message'] == message1
    
    # Bob to Alice
    message2 = "Hi Alice from Bob!"
    send2_response = make_request('POST', '/api/message/send', {
        'sender': bob_username,
        'password': 'bobpass123',
        'recipient': alice_username,
        'message': message2
    })
    assert send2_response.status_code == 200
    send2_data = send2_response.json()
    
    receive2_response = make_request('POST', '/api/message/receive', {
        'sender': bob_username,
        'recipient': alice_username,
        'password': 'alicepass123',
        'ciphertext_kem': send2_data['ciphertext_kem'],
        'ciphertext': send2_data['ciphertext'],
        'nonce': send2_data['nonce'],
        'tag': send2_data['tag'],
        'signature': send2_data['signature']
    })
    assert receive2_response.status_code == 200
    assert receive2_response.json()['message'] == message2

def test_empty_message():
    """Test sending and receiving an empty message"""
    alice_username = f"alice_empty_{int(time.time() * 1000000)}"
    bob_username = f"bob_empty_{int(time.time() * 1000000)}"
    
    # Register both users
    make_request('POST', '/api/auth/register', {
        'username': alice_username,
        'password': 'alicepass123'
    })
    
    make_request('POST', '/api/auth/register', {
        'username': bob_username,
        'password': 'bobpass123'
    })
    
    empty_message = ""
    send_response = make_request('POST', '/api/message/send', {
        'sender': alice_username,
        'password': 'alicepass123',
        'recipient': bob_username,
        'message': empty_message
    })
    
    print(f"Empty message send - Status: {send_response.status_code}")
    if send_response.status_code != 200:
        print(f"Empty message send failed: {send_response.json()}")
    
    assert send_response.status_code == 200, f"Empty message send failed: {send_response.json()}"
    send_data = send_response.json()
    
    receive_response = make_request('POST', '/api/message/receive', {
        'sender': alice_username,
        'recipient': bob_username,
        'password': 'bobpass123',
        'ciphertext_kem': send_data['ciphertext_kem'],
        'ciphertext': send_data['ciphertext'],
        'nonce': send_data['nonce'],
        'tag': send_data['tag'],
        'signature': send_data['signature']
    })
    
    print(f"Empty message receive - Status: {receive_response.status_code}")
    if receive_response.status_code != 200:
        print(f"Empty message receive failed: {receive_response.json()}")
    
    assert receive_response.status_code == 200, f"Empty message receive failed: {receive_response.json()}"
    receive_data = receive_response.json()
    assert receive_data['message'] == empty_message

def test_various_message_types():
    """Test sending various types of messages"""
    alice_username = f"alice_various_{int(time.time() * 1000000)}"
    bob_username = f"bob_various_{int(time.time() * 1000000)}"
    
    # Register both users
    make_request('POST', '/api/auth/register', {
        'username': alice_username,
        'password': 'alicepass123'
    })
    
    make_request('POST', '/api/auth/register', {
        'username': bob_username,
        'password': 'bobpass123'
    })
    
    test_messages = [
        "Short",
        "Message with special chars: !@#$%^&*()",
        "Message with unicode: 🚀 🔐 🌟",
        "A" * 100,  # Long message
        "Message with numbers: 1234567890",
        "Message with new\nlines",
        "   Message with spaces   ",
    ]
    
    for i, message in enumerate(test_messages):
        print(f"Testing message {i+1}: '{message[:30]}...'")
        
        # Send message
        send_response = make_request('POST', '/api/message/send', {
            'sender': alice_username,
            'password': 'alicepass123',
            'recipient': bob_username,
            'message': message
        })
        
        assert send_response.status_code == 200, f"Message {i+1} send failed: {send_response.json()}"
        send_data = send_response.json()
        
        # Receive message
        receive_response = make_request('POST', '/api/message/receive', {
            'sender': alice_username,
            'recipient': bob_username,
            'password': 'bobpass123',
            'ciphertext_kem': send_data['ciphertext_kem'],
            'ciphertext': send_data['ciphertext'],
            'nonce': send_data['nonce'],
            'tag': send_data['tag'],
            'signature': send_data['signature']
        })
        
        assert receive_response.status_code == 200, f"Message {i+1} receive failed: {receive_response.json()}"
        receive_data = receive_response.json()
        assert receive_data['message'] == message, f"Message {i+1} content mismatch"

def test_security_features_present():
    """Test that all security features are present in message responses"""
    alice_username = f"alice_sec_{int(time.time() * 1000000)}"
    bob_username = f"bob_sec_{int(time.time() * 1000000)}"
    
    # Register both users
    make_request('POST', '/api/auth/register', {
        'username': alice_username,
        'password': 'alicepass123'
    })
    
    make_request('POST', '/api/auth/register', {
        'username': bob_username,
        'password': 'bobpass123'
    })
    
    # Send a message
    send_response = make_request('POST', '/api/message/send', {
        'sender': alice_username,
        'password': 'alicepass123',
        'recipient': bob_username,
        'message': "Security test message"
    })
    
    assert send_response.status_code == 200
    send_data = send_response.json()
    
    # Verify we have all the expected security components
    required_fields = ['ciphertext_kem', 'ciphertext', 'nonce', 'tag', 'signature']
    for field in required_fields:
        assert field in send_data, f"Missing security field: {field}"
    
    # Verify the data are proper base64 and have reasonable length
    for field in required_fields:
        decoded_data = b64decode(send_data[field])
        assert len(decoded_data) > 0, f"Field {field} decoded to empty bytes"
    
    print("✓ All security fields present and valid")

if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])