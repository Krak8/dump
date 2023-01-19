import os
import jwt
from datetime import datetime, timedelta
from flask import Flask, render_template, request, send_from_directory, jsonify, session, redirect
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'secretkey'
app.config['UPLOAD_FOLDER'] = './cdn'

users = {'username': 'password'}

# JWT secret key
jwt_secret = 'jwtsecretkey'

# Allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# function to check if file is allowed
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# index endpoint
@app.route('/')
def index():
    return 'Welcome to the file server'

# upload endpoint
@app.route('/u', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return jsonify({'message': 'File uploaded successfully'}), 200
    # check if user is logged in
    if 'username' in session:
        return render_template('upload.html')
    else:
        return redirect('/login')

# serve file endpoint
@app.route('/s/<path:filename>')
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# login endpoint
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            payload = {'username': username}
            token = jwt.encode(payload, 'secret', algorithm='HS256')
            session['token'] = token
            return redirect('/v')
    return render_template('login.html')

# logout endpoint
@app.route('/logout')
def logout():
    # remove the token from session
    session.pop('token', None)
    # redirect user to the login page
    return redirect('/login')

# view files endpoint
@app.route('/v')
def view_files():
    token = request.headers.get('Authorization')
    if token:
        try:
            token = token.replace("Bearer ", "")
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
            return render_template('view_files.html', files=os.listdir('./cdn'))
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    else:
        return jsonify({'error': 'Token is missing'}), 401

if __name__ == '__main__':
    app.run(port=25500, host='0.0.0.0', debug=True)