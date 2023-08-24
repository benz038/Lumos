from flask import Flask, redirect, request, session
import requests

from flask import Flask, render_template, url_for, redirect, flash, request, redirect,send_from_directory
from werkzeug.utils import secure_filename
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os
#import magic
import urllib.request
print("All modules loaded...")

# dauth configuration
# At the top of your code, after importing Flask and other modules
DAUTH_CLIENT_ID = "kYsE8Z7gKhwpjrRQ"
DAUTH_CLIENT_SECRET = "r1ak.JcvD098RhHsxlQMDsK~hLg6_G4X"
DAUTH_REDIRECT_URI = "http://localhost:8000/callback"
DAUTH_AUTHORIZE_URL = "https://auth.delta.nitt.edu/authorize"
DAUTH_TOKEN_URL = "https://auth.delta.nitt.edu/api/oauth/token"
DAUTH_USER_URL = "https://auth.delta.nitt.edu/api/resources/user"





app = Flask(__name__)  # creating the Flask class object
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
app.config["SECRET_KEY"] = "secret"
db = SQLAlchemy(app)
app.app_context().push()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# //dauth login system





@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    else:
        flash('User Already Exist. Please try again.', 'danger')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Invalid password. Please try again.', 'danger')
    return render_template('login.html', form=form)


# UPLOADING FILE PART

 
def allowed_file(filename):
 return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload')
@login_required
def upload_form():
    conn = sqlite3.connect('file_database.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, course TEXT, semester TEXT, subject TEXT, filename TEXT)')
    conn.commit()
    c.execute('SELECT * FROM files')
    files = c.fetchall()
    conn.close()
    return render_template('upload.html', files=files)


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        # check if the post request has the files part
        if 'files[]' not in request.files:
            flash('No file part')
            return redirect(request.url)

        course = request.form['course']
        semester = request.form['semester']
        subject = request.form['subject']
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], course, semester,subject)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        files = request.files.getlist('files[]')
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(folder_path, filename))

                # Save the filename as a BLOB in the database
                with open(os.path.join(folder_path, filename), 'rb') as f:
                    data = f.read()
                    conn = sqlite3.connect('file_database.db')
                    c = conn.cursor()
                    c.execute('INSERT INTO files (course, semester, subject, filename) VALUES (?, ?, ?, ?)', (course, semester, subject, filename))
                    conn.commit()
                    conn.close()
        flash('File(s) successfully uploaded')
        return redirect('/upload')
    return render_template('upload.html')    

@app.route('/MCA-SEM1-OS')
@login_required
def MCA_page():
    files = os.listdir('static/MCA/SEM1/OS')
    return render_template('MCA1.html', files=files)

@app.route('/BTECH-page')
@login_required
def BTECH_page():
    files = os.listdir('static/BTECH/SEM1/OS')
    return render_template('BTECH.html', files=files)

@app.route('/download/<path:filename>')
@login_required
def download_file(filename):
    return send_from_directory('static', filename, as_attachment=True)



@app.route('/')  # decorator defines the
@login_required
def index():
    return render_template('index.html')

@app.route('/mca')  # decorator defines the
@login_required
def mca():
    return render_template('mca.html')

@app.route('/sem1')  # decorator defines the
@login_required
def sem1():
    return render_template('sem1.html')

@app.route('/about')  # decorator defines the
@login_required
def about():
    return render_template('about.html', name= "Deepak")

@app.route('/material')  # decorator defines the
@login_required
def material():
    return render_template('material.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True,port=8000)