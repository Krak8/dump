import os
from flask import Flask, request, jsonify, render_template, session
from flask_sslify import SSLify
import jwt

app = Flask(__name__)
app.secret_key = 'secret'

users = {'username': 'password'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    if username not in users or users[username] != password:
        return jsonify({'error': 'Invalid credentials'}), 401
    token = jwt.encode({'username': username}, app.secret_key, algorithm='HS256')
    session['token'] = token
    return jsonify({'token': token.decode('utf-8')})

@app.route('/upload')
def upload():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token is missing'}), 401
    try:
        data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
    except:
        return jsonify({'error': 'Invalid token'}), 401
    # handle file upload
    return jsonify({'message': 'File uploaded'})

@app.route('/view_files')
def view_files():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token is missing'}), 401
    try:
        data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
    except:
        return jsonify({'error': 'Invalid token'}), 401
    # handle fetching and displaying of uploaded files
    return render_template('view_files.html')

if __name__ == '__main__':
    sslify = SSLify(app)
    app.run(port=25500, host='0.0.0.0', debug=True)

