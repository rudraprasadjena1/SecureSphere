# tests\seed_users.py
import sys
import os
import random
import requests
import time

# --- API Configuration ---
API_BASE_URL = "http://127.0.0.1:5000/api"

def generate_users_via_api(num_users=30):
    """
    Seeds the database by calling the /register API endpoint.
    This script follows the new server-side key generation flow.
    """
    print("--- Starting API-based user seeding ---")
    print(f"Targeting API at: {API_BASE_URL}")

    first_names = ["Sophia", "Jackson", "Emma", "Aiden", "Olivia", "Lucas", "Ava", "Liam",
                   "Mia", "Noah", "Isabella", "Ethan", "Riley", "Mason", "Zoe"]
    
    domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"]

    created_count = 0
    login_credentials = []  # Store credentials for login
    
    for i in range(num_users):
        base_name = random.choice(first_names)
        username = f"{base_name}{random.randint(100, 999)}"
        email = f"{username.lower()}@{random.choice(domains)}"  # Generate email
        password = "password123" # Use a consistent password for all test users

        try:
            # --- Step 1: Construct the JSON payload with email ---
            register_payload = {
                "username": username,
                "email": email,  # Add email field
                "password": password
            }

            # --- Step 2: Make the HTTP POST request to register ---
            register_response = requests.post(f"{API_BASE_URL}/auth/register", json=register_payload)

            # --- Step 3: Check the registration response ---
            if register_response.status_code == 200:
                # Extract user ID from response if available
                response_data = register_response.json()
                user_id = response_data.get('user_id', 'N/A')
                
                print(f"[{created_count + 1}/{num_users}] SUCCESS: Registered user '{username}'.")
                created_count += 1
                
                # Store credentials for later display
                login_credentials.append({
                    'username': username,
                    'password': password,
                    'user_id': user_id
                })
                
                # --- Step 4 (Optional but recommended): Log in the user to set status ---
                if random.random() > 0.4: # 60% chance to log in
                    login_payload = {"username": username, "password": password}
                    login_response = requests.post(f"{API_BASE_URL}/auth/login", json=login_payload)
                    if login_response.status_code == 200:
                        print(f"    - INFO: Logged in '{username}' and set status to online.")
                    else:
                        print(f"    - WARN: Could not log in '{username}' after registration.")
                        
            elif register_response.status_code == 400:
                error_message = register_response.json().get("error", "Unknown error")
                print(f"INFO: Skipped '{username}' - {error_message}")
            else:
                print(f"FAILED to register '{username}'. Status: {register_response.status_code}, Response: {register_response.text}")

        except requests.exceptions.ConnectionError:
            print("\nFATAL: Connection to the Flask server failed.")
            print(f"Please make sure your backend application is running at {API_BASE_URL}")
            return
        except Exception as e:
            print(f"An unexpected script error occurred for {username}: {e}")
            
        time.sleep(0.05)

    print(f"\n--- Seeding complete. Created {created_count} new users by calling the registration API. ---")
    
    # Display login credentials
    print("\n" + "="*60)
    print("LOGIN CREDENTIALS - Use these to test the contact list:")
    print("="*60)
    
    for i, creds in enumerate(login_credentials, 1):
        print(f"{i}. Username: {creds['username']}")
        print(f"   Password: {creds['password']}")
        print(f"   User ID: {creds['user_id']}")
        print()
    
    print("="*60)
    print("You can now log in with any of these credentials to see the contact list!")
    print("All users share the same password: 'password123'")

if __name__ == "__main__":
    generate_users_via_api(30)