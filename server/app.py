from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore, auth
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import re
from collections import defaultdict
import requests
import os

app = Flask(__name__)
CORS(app)

cred = credentials.Certificate('credentials.json')
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
            'metadata': {},
            'reads': {
                "art": 0,
                "business": 0,
                "entertainment" : 0,
                "general": 0,
                "health": 0,
                "music": 0,
                "science": 0,
                "sports": 0,
                "technology": 0,
            },
            'saves': {
                "art": 0,
                "business": 0,
                "entertainment": 0,
                "general": 0,
                "health": 0,
                "music": 0,
                "science": 0,
                "sports": 0,
                "technology": 0,
            },
        })

        return jsonify({'status': 'success', 'message': 'Signup successful'}), 201

    except firebase_admin.auth.EmailAlreadyExistsError:
        return jsonify({'status': 'failure', 'message': 'Email already exists'}), 400
    except Exception as e:
        return jsonify({'status': 'failure', 'message': str(e)}), 400

@app.route('/get_user_info', methods=['GET'])
def get_user_info():
    email = request.args.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    try:
        users_ref = db.collection('users')
        query = users_ref.where('email', '==', email).stream()

        user_info = None
        for user in query:
            user_info = user.to_dict()
            break
        if not user_info:
            return jsonify({'error': 'User not found'}), 404
        return jsonify(user_info), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# News API configuration
NEWS_API_KEY = '86ed1e156ef64eeaa611c3bfc07a61d3'  # Replace with your actual News API key
NEWS_API_URL = 'https://newsapi.org/v2/top-headlines'


def aggregate_preferences(user_data):
    aggregated = defaultdict(int)
    if 'reads' in user_data:
        for category, count in user_data['reads'].items():
            aggregated[category] += count * 1  # Weight for reads
    if 'saves' in user_data:
        for category, count in user_data['saves'].items():
            aggregated[category] += count * 2  # Higher weight for saves
    return aggregated


def fetch_articles(categories):
    articles = []
    for category in categories:
        params = {
            'category': category,
            'apiKey': NEWS_API_KEY,
            'pageSize': 5  # Limit the number of articles per category
        }
        response = requests.get(NEWS_API_URL, params=params)
        if response.status_code == 200:
            articles.extend(response.json().get('articles', []))
    return articles


@app.route('/get_recommendations', methods=['GET'])
def get_recommendations():
    email = request.args.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    try:
        # Get user data from Firestore
        users_ref = db.collection('users')
        query = users_ref.where('email', '==', email).stream()

        user_data = None
        for user in query:
            user_data = user.to_dict()
            break

        if not user_data:
            return jsonify({'error': 'User not found'}), 404

        user_preferences = aggregate_preferences(user_data)
        sorted_preferences = sorted(user_preferences.items(), key=lambda item: item[1], reverse=True)
        preferred_categories = [category for category, _ in sorted_preferences]

        recommended_articles = fetch_articles(preferred_categories)
        print(preferred_categories)

        return jsonify(recommended_articles), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/increment_read_count', methods=['POST'])
def increment_read_count():
    data = request.json
    email = data.get('email')
    category = data.get('category').lower()

    if not email or not category:
        return jsonify({'error': 'Email and category are required'}), 400

    try:
        # Get user data from Firestore
        users_ref = db.collection('users')
        query = users_ref.where('email', '==', email).stream()

        user_data = None
        user_id = None
        for user in query:
            user_data = user.to_dict()
            user_id = user.id
            break

        if not user_data:
            return jsonify({'error': 'User not found'}), 404

        users_ref.document(user_id).update({
            f'reads.{category}': firestore.Increment(1)
        })

        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
