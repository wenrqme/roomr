import os
from flask import Flask, url_for, flash, render_template, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
import datetime 
from datetime import datetime
import base64
# import bcrypt 
from hashlib import sha512
from werkzeug.security import generate_password_hash, check_password_hash
# from cryptography.fernet import Ferne
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, DateField, PasswordField, BooleanField, FileField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
import ssl
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from flask_mail import Mail, Message

"""
For login
"""
app = Flask(__name__)
app.config["SECRET_KEY"] = "oEHYBreJ2QSefBdUhD19PkxC"
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)
socketio = SocketIO(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

"""
For email authentication with Google's SMTP server
"""
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "roomr.confirmation@gmail.com"
app.config["MAIL_PASSWORD"] = "roomr123$"
mail = Mail(app)

"""
Database Stuff
"""
appdir = os.path.abspath(os.path.dirname(__file__))

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(appdir, 'library.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)




"""
User Class & Password Hashing
"""
class User(UserMixin, db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(64), unique=True, index=True, nullable=False)
    fname = db.Column(db.String(32), index=True, nullable=False)
    lname = db.Column(db.String(32), index=True, nullable=False)
    dob = db.Column(db.DateTime, index=True,nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    confirmed = db.Column(db.Boolean(), default=False)

    profilePicture = db.Column(db.String(3), index=True, nullable=True)
    location = db.Column(db.String(32), index=True, nullable=False)
    gender = db.Column(db.String(6), index=True, nullable=False)
    bio = db.Column(db.String(500), index=True, nullable=True)
    smoker = db.Column(db.String(3), index=True, nullable=False)
    sleep = db.Column(db.String(5), index=True, nullable=False)
    genderPreferences = db.Column(db.String(3), index=True, nullable=False)
    cleanliness = db.Column(db.String(5), index = True, nullable = False)

    @property
    def password(self):
        raise AttributeError("password is write only")
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(app.config['SECRET_KEY'], expiration)
        return s.dumps({"confirm": self.id}).decode("utf-8")

    def confirm(self, token):
        s = Serializer(app.config["SECRET_KEY"])
        try:
            data = s.loads(token.encode("utf-8"))
        except Exception:
            return False
        if data.get("confirm") != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        db.session.commit()
        return True
    

db.create_all()



"""
Login and Signup
"""
#add error notes on HTML template
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Submit")

class SignupForm(FlaskForm):
    fname = StringField("First Name", validators=[DataRequired()])
    lname = StringField("Last Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email(), EqualTo('email2', message='Emails must match')])
    email2 = StringField("Confirm Email", validators=[DataRequired(), Email()])
    dob = DateField("Date of Birth", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])

    profilePicture = FileField("Profile Picture")
    location = StringField("Location", validators=[DataRequired()])
    gender = SelectField("Gender", choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')], validators=[DataRequired()])
    bio = TextAreaField("Bio", validators=[DataRequired()])
    smoker = SelectField("Do you smoke?", choices=[('yes', 'Yes'), ('no', 'No')], validators=[DataRequired()])
    sleepPattern = SelectField("Sleep pattern", choices=[('late', 'Night Owl'), ('early', 'Early Bird')], validators=[DataRequired()])
    cleanliness = SelectField("Cleanliness", choices=[('messy', 'Messy'),('average', 'Average'), ('clean', 'Clean')], validators=[DataRequired()])
    genderPreferences = SelectField("Gender Preference", choices=[('male', 'Male Only'), ('female', 'Female Only'), ('any', 'Any')], validators=[DataRequired()])
    
    submit = SubmitField("Submit")
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError("Please use a different email")

class ProfileForm(FlaskForm):
    profilePicture = FileField("Profile Picture")
    location = StringField("Location", validators=[DataRequired()])
    gender = SelectField("Gender", choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')], validators=[DataRequired()])
    bio = TextAreaField("Bio", validators=[DataRequired()])
    smoker = SelectField("Do you smoke?", choices=[('yes', 'Yes'), ('no', 'No')], validators=[DataRequired()])
    sleepPattern = SelectField("Sleep pattern", choices=[('late', 'Night Owl'), ('early', 'Early Bird')], validators=[DataRequired()])
    cleanliness = SelectField("Cleanliness", choices=[('messy', 'Messy'),('average', 'Average'), ('clean', 'Clean')], validators=[DataRequired()])
    
    genderPreferences = SelectField("Gender Preference", choices=[('male', 'Male Only'), ('female', 'Female Only'), ('any', 'Any')], validators=[DataRequired()])
    submit = SubmitField("Submit")

#temporary chat form
class ChatForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    room = StringField('Room', validators=[DataRequired()])
    submit = SubmitField('Enter Chatroom')

"""
roomr pages
"""
#home page
@app.route('/', methods=["GET"])
def home():
    if current_user.is_authenticated == True:
        users = match()
        return render_template("home.html", users = users)
    else:
        return render_template("home.html")
    #need links to login or create an account

#sign-up page
@app.route("/signup", methods=["GET","POST"])
def signup():
    fname, lname, email, dob, password = None, None, None, None, None
    form = SignupForm()
    print(form.validate_on_submit())
    if form.validate_on_submit():
        fname = form.fname.data
        lname = form.lname.data
        email = form.email.data
        dob = form.dob.data
        userPassword = form.password.data

        profilePicture = form.profilePicture.data
        location = form.location.data
        gender = form.gender.data
        bio = form.bio.data
        smoker = form.smoker.data
        sleepPattern = form.sleepPattern.data
        genderPreferences = form.genderPreferences.data
        cleanliness = form.cleanliness.data
        
        user = User(email= email, fname= fname, lname=lname, dob= dob, password=userPassword, profilePicture = profilePicture, \
            location=location, cleanliness=cleanliness, gender=gender, \
            bio = bio, smoker=smoker, sleep=sleepPattern, genderPreferences = genderPreferences)
        db.session.add(user)
        db.session.commit()
        print("form validated and submitted!")
        token = user.generate_confirmation_token()
        app.config['SECRET_KEY'] = token
        print(f"{app.config['SECRET_KEY']} is the token")
        send_email(user.email, 'roomr Email Verification',
                   "email_Auth.txt", user, token=token)
        print("email sent!")
        return render_template('signupresp.html', user=user)
    elif request.method=="POST": 
        print("not validated")
        flash('Some information is incorrect')
    return render_template("signup.html", form=form)

#login page
@app.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print("is validated")
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get("next")
            if next is None or not next.startswith("/"):
                next = url_for("user")
            return redirect(next)
        flash("Invalid Username or password.")
    return render_template("login.html", form=form)

def send_email(to, subject, template, User, token):
    me = app.config["MAIL_USERNAME"]
    to = User.email
    msg = Message(subject, sender=app.config["MAIL_USERNAME"], recipients=[
                  to])
    with open(os.getcwd() + "\\templates\\" + template) as f:
        msg.body = f.read()
    url = url_for('confirm', token=token)
    msg.body += 'http://127.0.0.1:8080' + url
    mail.send(msg)

#logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("you have been logged out")
    return redirect(url_for("login"))

#edit profile page
@app.route("/user/edit", methods=["GET","POST"])
@login_required
def editProfile():
    profilePicture, location, gender, bio, smoker, sleepPattern, cleanliness, genderPreferences = None, None, None, None, None, None, None, None
    user = current_user

    prefill = {'profilePicture': str(user.profilePicture), 'location': str(user.location), 'gender':str(user.gender), 'bio':str(user.bio), 'smoker':str(user.smoker), 'sleepPattern':str(user.sleep), 'cleanliness':str(user.cleanliness), 'genderPreferences':str(user.genderPreferences)}
    form = ProfileForm(data=prefill)

    if form.validate_on_submit and request.method=="POST":
        user.profilePicture = form.profilePicture.data
        user.location = form.location.data
        user.gender = form.gender.data
        user.bio = form.bio.data
        user.smoker = form.smoker.data
        user.sleep = form.sleepPattern.data
        user.cleanliness = form.cleanliness.data
        user.genderPreferences = form.genderPreferences.data
        db.session.add(user)
        db.session.commit()
        print("form validated and submitted!")
        flash('Profile updated! :)')
        return render_template('edit_profile.html', form=form)
    elif request.method=="POST": 
        print("not validated")
        flash('Some information is incorrect')
    return render_template("edit_profile.html", form=form)

#viewing another user's profile page
@app.route("/user/view/<email>", methods=["GET"])
@login_required
def viewProfile(email):
    other_user = User.query.filter_by(email=email).first()
    if current_user.email == other_user.email: 
        return render_template("user.html")
    return render_template("view_user.html", other_user=other_user)

@app.route("/user", methods=["GET"])
@login_required
def user():
    return render_template("user.html")

@app.route('/chat')
def chat():
    """Chat room. The user's name and room must be stored in
    the session."""
    name = session.get('name', '')
    room = session.get('room', '')
    if name == '' or room == '':
        return redirect(url_for('.index'))
    return render_template('chat.html', name=name, room=room)

@app.route('/chatform', methods=["GET", "POST"])
def chatform():
    """Login form to enter a room."""
    form = ChatForm()
    if form.validate_on_submit():
        session['name'] = form.name.data
        session['room'] = form.room.data
        return redirect(url_for('.chat'))
    elif request.method == 'GET':
        form.name.data = session.get('name', '')
        form.room.data = session.get('room', '')
    return render_template('chatform.html', form=form)

@app.route("/confirm/<string:token>")
@login_required
def confirm(token):
    if current_user.confirmed:
        password
    elif current_user.confirm(token):
        db.session.commit()
        flash("Thank you for confirming your account.")
    else:
        flash("Your confirmation link is invalid or has expired")
    return redirect(url_for("home"))


def match():
    # gender
    users = None
    if current_user.genderPreferences == "any":
        # users = User.query.filter_by(genderPreferences=current_user.gender | genderPreferences='any').all()
        users = User.query.filter(or_(User.genderPreferences==current_user.gender, User.genderPreferences=='any')).all()
    elif current_user.genderPreferences == "male":
        users = User.query.filter(or_(User.gender=="male", User.gender=="other"), or_(User.genderPreferences==current_user.gender, User.genderPreferences=="any")).all()
    elif current_user.genderPreferences == "female":
        users = User.query.filter(or_(User.gender=="female", User.gender=="other"), or_(User.genderPreferences==current_user.gender, User.genderPreferences=="any")).all()
   
    return users

    # print(users)
    

""" 
email authentication
"""
# subject = "roomr Account Confirmation"
# sender = "roomr@mailinator.com"
# recipient = "asiegle@u.rochester.edu"


# #create the Message
# msg = MIMEMultipart("alternative")
# msg["Subject"] = subject
# msg["From"] = sender
# msg["To"] = recipient

# #Record the MIME types of both parts - text/plain and text/html
# part1 = MIMEText("hiHi", "plain")
# part2 = MIMEText("email_Auth.html", "html")

# #Send Message
# context = ssl.create_default_context()
# server, port = "127.0.0.1", 25
# with smtplib.SMTP_SSL(server, port, context=context) as s:
#     s.login(sender, "123") # this line makes it password restricted
#     s.sendmail(sender, recipient, msg.as_string())

""" 
chat functionality
"""
@socketio.on('joined', namespace='/chat')
def joined(message):
    """Sent by clients when they enter a room.
    A status message is broadcast to all people in the room."""
    room = session.get('room')
    join_room(room)
    emit('status', {'msg': session.get('name') + ' has entered the room.'}, room=room)

@socketio.on('text', namespace='/chat')
def text(message):
    """Sent by a client when the user entered a new message.
    The message is sent to all people in the room."""
    room = session.get('room')
    emit('message', {'msg': session.get('name') + ':' + message['msg']}, room=room)

@socketio.on('left', namespace='/chat')
def left(message):
    """Sent by clients when they leave a room.
    A status message is broadcast to all people in the room."""
    room = session.get('room')
    leave_room(room)
    emit('status', {'msg': session.get('name') + ' has left the room.'}, room=room)
""" 
running the app
"""
if __name__ == '__main__':
    # app.run()
    app.run(host='127.0.0.1', port=8080, debug=True)
    socketio.run(app)

