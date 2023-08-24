from flask import Flask, redirect, request, session, render_template, url_for, flash, send_from_directory
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from os import listdir
import sqlite3
import os
import requests
import logging

print("All modules loaded...")

# Configure the logging
# Create a custom logger
logger = logging.getLogger('my_logger')
logger.setLevel(logging.INFO)

# Create handlers
file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.INFO)

# Create formatters and add it to handlers
formatter = logging.Formatter('%(asctime)s - %(message)s')
file_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(file_handler)



# Dauth configuration
DAUTH_CLIENT_ID = "kYsE8Z7gKhwpjrRQ"
DAUTH_CLIENT_SECRET = "9EsOsf~XYuofif9KeK7iU3Fd7d03pM.W"
DAUTH_REDIRECT_URI = "http://localhost:8000/callback"
DAUTH_AUTHORIZE_URL = "https://auth.delta.nitt.edu/authorize"
DAUTH_TOKEN_URL = "https://auth.delta.nitt.edu/api/oauth/token"
DAUTH_USER_URL = "https://auth.delta.nitt.edu/api/resources/user"

app = Flask(__name__)
bcrypt = Bcrypt(app)

# //2^20 bytes or 16MB
UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
ALLOWED_EXTENSIONS = set(['pdf'])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
app.config["SECRET_KEY"] = "secret"
db = SQLAlchemy(app)
app.app_context().push()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'dauth_login'  # Redirect to DAuth login


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    dauth_id = db.Column(db.String(120), unique=True)  # DAuth unique identifier
    dauth_token = db.Column(db.String(255))  # DAuth token (if needed)
    upload_access = db.Column(db.String(10), default='reject')


# ... (existing classes, routes, and functions)

# DAuth login route
@app.route('/dauth_login')
def dauth_login():
    authorization_url = f"{DAUTH_AUTHORIZE_URL}?response_type=code&client_id={DAUTH_CLIENT_ID}&redirect_uri={DAUTH_REDIRECT_URI}&scope=user"  # Added user scope
    return redirect(authorization_url)

# DAuth callback route
@app.route('/callback')
def callback():
    code = request.args.get('code')
    data = {
        'client_id': DAUTH_CLIENT_ID,
        'client_secret': DAUTH_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DAUTH_REDIRECT_URI
    }
    response = requests.post(DAUTH_TOKEN_URL, data=data)

    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        print(response.text)
        return "Error in callback in token response"

    token_data = response.json()
    access_token = token_data['access_token']

    headers = {'Authorization': f'Bearer {access_token}'}
    user_response = requests.post(DAUTH_USER_URL, headers=headers)  # POST request to /api/resources/user

    if user_response.status_code != 200:
        print(f"Error: {user_response.status_code}")
        print(user_response.text)
        return "Error in callback in user_response-2"

    user_data = user_response.json()


    # Retrieve DAuth ID and email from user_data (adjust as needed)
    dauth_id = user_data['id']
    email = user_data['email']

    # Check if user exists in your database
    user = User.query.filter_by(dauth_id=dauth_id).first()

    if user is None:
        # Create a new user if not found
        user = User(username=email.split('@')[0], email=email, password="DAuthUser", dauth_id=dauth_id)
        db.session.add(user)
        db.session.commit()

    # Log the user in
    login_user(user)
    logger.info(f"User {user.username} logged in")
    return redirect(url_for('index'))

# Admin panel
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if current_user.username != '205121038':
        return redirect(url_for('index'))

    users = User.query.all()

    if request.method == 'POST':
        user_id = request.form['user_id']
        action = 'accept' if 'action' in request.form else 'reject'
        user = User.query.get(user_id)
        user.upload_access = action
        db.session.commit()

    return render_template('admin.html', users=users)


# UPLOADING FILE PART

 
def allowed_file(filename):
 return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload')
@login_required
def upload_form():
    if current_user.upload_access != 'accept' and current_user.username != '205121038':
        return redirect(url_for('index'))

    conn = sqlite3.connect('file_database.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS files (serial_no INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, course TEXT, subject TEXT, filename TEXT)') # Removed semester
    conn.commit()
    c.execute('SELECT * FROM files')
    files = c.fetchall()
    conn.close()
    return render_template('upload.html', files=files)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if current_user.upload_access != 'accept' and current_user.username != '205121038':
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        if 'files[]' not in request.files:
            flash('No file part')
            return redirect(request.url)

        course = request.form['course']
        subject = request.form['subject']
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], course, subject) # Removed semester
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        files = request.files.getlist('files[]')
        username = current_user.username

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(folder_path, filename))
                roll_number = current_user.username  # Assuming the username is the roll number
                logger.info(f'File uploaded: {filename} by roll number: {roll_number}')

                conn = sqlite3.connect('file_database.db')
                c = conn.cursor()
                c.execute('INSERT INTO files (username, course, subject, filename) VALUES (?, ?, ?, ?)', (username, course, subject, filename)) # Removed semester
                conn.commit()
                conn.close()

        flash('File(s) successfully uploaded')
        return redirect('/upload')
    return render_template('upload.html')


def get_files_for_subject(subject_name):
    subject_path = os.path.join('static', 'MCA', subject_name.replace(" ", "_"))
    if os.path.exists(subject_path):
        return os.listdir(subject_path)
    else:
        return []



@app.route('/static/<path:filename>')
@login_required
def download_file(filename):
    return send_from_directory('static', filename, as_attachment=True)



@app.route('/')  # decorator defines the
@login_required
def index():
    return render_template('index.html')

@app.route('/mca')
@login_required
def mca():
    subjects = [
    "PSP-Problem Solving and Programming",
    "MFCA-Mathematical Foundations of Computer Applications",
    "DLCO-Digital Logic and Computer Organization",
    "DSA-Data Structures and Applications",
    "OS-Operating Systems",
    "PSLP-Problem Solving Lab using Python",
    "DSLC-Data Structures Lab using C",
    "DAA-Design and Analysis of Algorithms",
    "DBMS-Database Management Systems",
    "PSM-Probability and Statistical Methods",
    "OOP-Object Oriented Programming",
    "CN-Computer Networks",
    "DBMSL-DBMS Lab",
    "CNL-Computer Networks Lab",
    "DMW-Data Mining and Warehousing",
    "CI-Computational Intelligence",
    "SE-Software Engineering",
    "AFM-Accounting and Financial Management",
    "DML-Data Mining Lab",
    "BC-Business Communication",
    "MLDL-Machine Learning and Deep Learning",
    "WTA-Web Technology and Its Applications",
    "PDC-Parallel and Distributed Computing",
    "PW-Project Work - Phase I",
    "IS-Information Security",
    "CC-Cloud Computing",
    "OB-Organizational Behaviour",
    "ISL-Information Security Lab",
    "CCL-Cloud Computing Lab"
]

    return render_template('mca.html', subjects=subjects)


@app.route('/subject/<subject_name>')
@login_required
def subject_page(subject_name):
    subject_path = os.path.join(app.config['UPLOAD_FOLDER'], 'MCA',subject_name)
    files = listdir(subject_path) if os.path.exists(subject_path) else "deepak"
    return render_template('subject_page.html', subject_name=subject_name, files=files)



@app.route('/about')  # decorator defines the
@login_required
def about():
    return render_template('about.html', name= "Deepak")


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    username = current_user.username
    logout_user()
    logger.info(f"User {username} logged out")
    return redirect(url_for('dauth_login'))


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True,port=8000)