from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore, auth
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import re
import os
app = Flask(__name__)
CORS(app)

cred = credentials.Certificate({
    "type": os.getenv("FIREBASE_TYPE"),
    "project_id": os.getenv("FIREBASE_PROJECT_ID"),
    "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
    "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
    "client_id": os.getenv("FIREBASE_CLIENT_ID"),
    "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
    "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_CERT_URL"),
    "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_CERT_URL")
})
firebase_admin.initialize_app(cred)
db = firestore.client()


def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not 'username' in data or not 'password' in data:
        return jsonify({'status': 'failure', 'message': 'Missing credentials'}), 400

    username = data['username']
    password = data['password']

    if not is_valid_email(username):
        return jsonify({'status': 'failure', 'message': 'Invalid email format'}), 400

    try:
        user = auth.get_user_by_email(username)

        doc_ref = db.collection('users').document(user.uid)
        doc = doc_ref.get()
        if doc.exists:
            user_data = doc.to_dict()
            if check_password_hash(user_data['password_hash'], password):
                return jsonify({'status': 'success', 'message': 'Login successful'}), 200
            else:
                return jsonify({'status': 'failure', 'message': 'Invalid credentials'}), 401
        else:
            return jsonify({'status': 'failure', 'message': 'User not found'}), 404

    except auth.UserNotFoundError:
        return jsonify({'status': 'failure', 'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'status': 'failure', 'message': str(e)}), 400

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or not 'username' in data or not 'password' in data or not 'email' in data:
        return jsonify({'status': 'failure', 'message': 'Missing credentials'}), 400

    username = data['username']
    password = data['password']
    email = data['email']

    if not is_valid_email(email):
        return jsonify({'status': 'failure', 'message': 'Invalid email format'}), 400

    try:
        user = auth.create_user(
            email=email,
            password=password,
            display_name=username
        )

        db.collection('users').document(user.uid).set({
            'username': username,
            'email': email,
            'password_hash': generate_password_hash(password),
            'display_name': username,
            'created_at': datetime.datetime.utcnow(),
            'updated_at': datetime.datetime.utcnow(),
            'role': 'user',
            'metadata': {}
        })

        return jsonify({'status': 'success', 'message': 'Signup successful'}), 201

    except firebase_admin.auth.EmailAlreadyExistsError:
        return jsonify({'status': 'failure', 'message': 'Email already exists'}), 400
    except Exception as e:
        return jsonify({'status': 'failure', 'message': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True)
