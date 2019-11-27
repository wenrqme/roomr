import os
import json
from flask import Flask, url_for, flash, render_template, redirect, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
import datetime 
from datetime import datetime, date
import base64
# import bcrypt 
from hashlib import sha512
from werkzeug.security import generate_password_hash, check_password_hash
# from cryptography.fernet import Ferne
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, DateField, PasswordField, BooleanField, FileField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
import ssl
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer
from werkzeug.utils import secure_filename

from flask_socketio import SocketIO, send, emit, join_room, leave_room
from flask_mail import Mail, Message
from flask_uploads import UploadSet, IMAGES , configure_uploads

"""
For login
"""
app = Flask(__name__)
app.config["SECRET_KEY"] = "oEHYBreJ2QSefBdUhD19PkxC"
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)
socketio = SocketIO(app)



s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

with app.open_resource("usaCities.json", 'r') as fin:
    cities = json.load(fin)

states = ["Alabama","Alaska","Arizona","Arkansas","California","Colorado", \
  "Connecticut","Delaware","Florida","Georgia","Hawaii","Idaho","Illinois", \
  "Indiana","Iowa","Kansas","Kentucky","Louisiana","Maine","Maryland", \
  "Massachusetts","Michigan","Minnesota","Mississippi","Missouri","Montana", \
  "Nebraska","Nevada","New Hampshire","New Jersey","New Mexico","New York", \
  "North Carolina","North Dakota","Ohio","Oklahoma","Oregon","Pennsylvania", \
  "Rhode Island","South Carolina","South Dakota","Tennessee","Texas","Utah", \
  "Vermont","Virginia","Washington","West Virginia","Wisconsin","Wyoming"]

        

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

"""
For email authentication with Google's SMTP server
"""
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "roomr.official@gmail.com"
app.config["MAIL_PASSWORD"] = "roomrroomr123$"
mail = Mail(app)

"""
Database Stuff
"""
appdir = os.path.abspath(os.path.dirname(__file__))

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(appdir, 'library.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

app.config['UPLOADED_PHOTOS_DEST'] = os.path.join(appdir, 'profile-pictures') # you'll need to create a folder named uploads



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
    
    profilePicture = db.Column(db.String(64), nullable=True)
    state = db.Column(db.String(32), index=True, nullable=False)
    city = db.Column(db.String(32), index=True, nullable=False)
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
        # s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps([str(self.id)])
        # return s.dumps({"confirm": self.id})

    def confirm(self, token):
        # s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        try:
            # print(token)
            data = s.loads(token, max_age=3600)
        except Exception as e:
            print(e)
            # print(e.payload)
            return False
        # if data.get("confirm") != self.id:
        if str(data[0]) != str(self.id):
            # print(f"!=, {data[0]}, {self.id} ")
            return False
        self.confirmed = True
        db.session.add(self)
        db.session.commit()
        return True
    

db.create_all()



"""
Login and Signup
"""
images = UploadSet('images', IMAGES, default_dest=lambda app: "profile-pictures")
configure_uploads(app, images)

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

    profilePicture = FileField("Profile Picture", validators=[FileAllowed(images, 'Images only!')])
    state = SelectField("State", choices=[(state, state) for state in states])
    city = SelectField("City", choices=[])
    gender = SelectField("Gender", choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')], validators=[DataRequired()])
    bio = TextAreaField("Bio", validators=[DataRequired()])
    smoker = SelectField("Do you smoke?", choices=[('yes', 'Yes'), ('no', 'No')], validators=[DataRequired()])
    sleepPattern = SelectField("Sleep pattern", choices=[('late', 'Night Owl'), ('early', 'Early Bird')], validators=[DataRequired()])
    cleanliness = SelectField("Cleanliness", choices=[('messy', 'Messy'),('average', 'Average'), ('clean', 'Clean')], validators=[DataRequired()])
    #price = SelectField("Price range", [('low', '$'),('average', '$$'), ('high', '$$$')], validators=[DataRequired()])
    #noiselevel = SelectField("How loud are you?", [('quiet', 'Quiet'),('average', 'Average'), ('loud', 'Loud')], validators=[DataRequired()])
    #petfriendly = SelectField("Pet-friendly?", [('yes', 'Yes'),('no', 'No')], validators=[DataRequired()])
    genderPreferences = SelectField("Gender Preference", choices=[('male', 'Male Only'), ('female', 'Female Only'), ('any', 'Any')], validators=[DataRequired()])
    
    submit = SubmitField("Submit")
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError("Please use a different email")

class ProfileForm(FlaskForm):
    profilePicture = FileField("Profile Picture", validators=[FileAllowed(images, 'Images only!')])
    state = SelectField("State", choices=[(state, state) for state in states])
    city = SelectField("City", choices=[])
    gender = SelectField("Gender", choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')], validators=[DataRequired()])
    bio = TextAreaField("Bio", validators=[DataRequired()])
    smoker = SelectField("Do you smoke?", choices=[('yes', 'Yes'), ('no', 'No')], validators=[DataRequired()])
    sleepPattern = SelectField("Sleep pattern", choices=[('late', 'Night Owl'), ('early', 'Early Bird')], validators=[DataRequired()])
    cleanliness = SelectField("Cleanliness", choices=[('messy', 'Messy'),('average', 'Average'), ('clean', 'Clean')], validators=[DataRequired()])
    
    genderPreferences = SelectField("Gender Preference", choices=[('male', 'Male Only'), ('female', 'Female Only'), ('any', 'Any')], validators=[DataRequired()])
    submit = SubmitField("Submit")

@app.route('/city/<state>')
def city(state):
    currentCities = cities[state]

    cityArray = []

    for city in currentCities:
        cityObj = {}
        cityObj['state'] = state
        cityObj['name'] = city
        cityArray.append(cityObj)

    return jsonify({'cities' : cityArray})

#temporary chat form
class ChatForm(FlaskForm):
    room = StringField('Room', validators=[DataRequired()])
    submit = SubmitField('Enter Chatroom')

"""
roomr pages
"""
#home page
@app.route('/', methods=["GET"])
def home():
    if current_user.is_authenticated == True:
        print("main home")
        print(current_user.state, current_user.city)
        users = findSuggestions()
        points = softPreferences(users)
        points = dict(points)
        return render_template("home.html", users = users, points = points)
    else:
        print("else home")
        return render_template("home.html")
    # return render_template("home.html")

    #need links to login or create an account

#sign-up page
@app.route("/signup", methods=["GET","POST"])
def signup():
    # profilePicture = request.files['profilePicture']
    fname, lname, email, dob, password = None, None, None, None, None
    form = SignupForm()
    prefill = {'state': 'Alabama'}
    form = SignupForm(data=prefill)
    form.city.choices = [(city, city) for city in cities[form.state.data]]
    # print(form.validate_on_submit())
    if form.validate_on_submit():
        fname = form.fname.data
        lname = form.lname.data
        email = form.email.data
        dob = form.dob.data
        userPassword = form.password.data

        # profilePicture = form.profilePicture.data
        # filename = secure_filename(profilePicture.filename)
        # profilePicture.save(os.path.join(app.instance_path, 'photos', filename))
        if form.profilePicture.data != None:
            filename = images.save(form.profilePicture.data)
            file_url = images.url(filename)
            profilePicture = file_url
        else:
            profilePicture = url_for('static', filename="generic-profile-picture.jpg")
        # filename = secure_filename(profilePicture.filename)
        # print(file_url)

        state = form.state.data
        city = form.city.data
        gender = form.gender.data
        bio = form.bio.data
        smoker = form.smoker.data
        sleepPattern = form.sleepPattern.data
        genderPreferences = form.genderPreferences.data
        cleanliness = form.cleanliness.data
        
        #add profilePicture=profilePicture to user
        user = User(email= email, fname= fname, lname=lname, dob= dob, password=userPassword, profilePicture=profilePicture, \
            state=state, city=city, cleanliness=cleanliness, gender=gender, \
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
    # with open(os.getcwd() + "\\templates\\" + template) as f:
    with open(os.getcwd() + "/templates/" + template) as f:
        msg.body = f.read()
    # url = url_for('confirm', token=token)
    # msg.body += 'http://127.0.0.1:8080' + url
    msg.body += url_for('confirm', token=token, _external=True)
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
    profilePicture, state, city, gender, bio, smoker, sleepPattern, cleanliness, genderPreferences = None, None, None, None, None, None, None, None, None
    user = current_user

    prefill = {'state': str(user.state), 'city': str(user.city), 'gender':str(user.gender), 'bio':str(user.bio), 'smoker':str(user.smoker), 'sleepPattern':str(user.sleep), 'cleanliness':str(user.cleanliness), 'genderPreferences':str(user.genderPreferences)}
    form = ProfileForm(data=prefill)
    form.city.choices = [(city, city) for city in cities[str(user.state)]]
    #form.city.data = user.city

    if form.validate_on_submit and request.method=="POST":
        # user.profilePicture = form.profilePicture.data
        if form.profilePicture.data != None:
            print(form.profilePicture.data)
            filename = images.save(form.profilePicture.data)
            file_url = images.url(filename)
            user.profilePicture = file_url
        # else:
            # user.profilePicture = url_for('static', filename="generic-profile-picture.jpg", _external=True)

        user.state = form.state.data    
        user.city = form.city.data
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

#chat room page
@app.route('/chat')
@login_required
def chat():
    room = session.get('room', '')
    name = session.get('name', '')
    return render_template('chat.html', name=name, room=room)

#private chat room page
@app.route('/privatechat/<email>')
@login_required
def privatechat(email):
    user = User.query.filter_by(email=email).first()
    room = "".join(sorted([user.email, current_user.email]))
    name = current_user.fname
    session['room'] = room
    session['name'] = name
    return render_template('privatechat.html', user=user, name=name, room=room)

#login page to enter a chatroom
@app.route('/chatform', methods=["GET", "POST"])
@login_required
def chatform():
    form = ChatForm()
    if form.validate_on_submit():
        session['room'] = form.room.data
        session['name'] = current_user.fname
        return redirect(url_for('.chat'))
    elif request.method == 'GET':
        form.room.data = session.get('room', '')
    return render_template('chatform.html', form=form)

@app.route("/confirm/<string:token>")
@login_required
def confirm(token):
    if current_user.confirmed:
        print("already confirmed")
        # password
    elif current_user.confirm(token):
        print("confirming...")
        # user = current_user
        # user.confirmed = True
        # db.session.add(user)
        db.session.commit()
        flash("Thank you for confirming your account.")
    else:
        flash("Your confirmation link is invalid or has expired")
    return redirect(url_for("home"))

#filtering hard preferences
def findSuggestions():
    """
    hard preferences 
    gender, location
    """
    users = None
    if current_user.genderPreferences == "any":
        # users = User.query.filter_by(genderPreferences=current_user.gender | genderPreferences='any').all()
        users = User.query.filter(or_(User.genderPreferences==current_user.gender, User.genderPreferences=='any'), User.state==current_user.state, User.city==current_user.city, User.id!=current_user.id).all()
    elif current_user.genderPreferences == "male":
        users = User.query.filter(or_(User.gender=="male", User.gender=="other"), or_(User.genderPreferences==current_user.gender, User.genderPreferences=="any"), User.state==current_user.state, User.city==current_user.city, User.id!=current_user.id).all()
    elif current_user.genderPreferences == "female":
        users = User.query.filter(or_(User.gender=="female", User.gender=="other"), or_(User.genderPreferences==current_user.gender, User.genderPreferences=="any"), User.state==current_user.state, User.city==current_user.city, User.id!=current_user.id).all()

    return users

    # print(users)

#calculating percentage match for soft preferences
def softPreferences(users):
    points = []
    for user in users:
        total = 0
        if current_user.smoker == user.smoker:
            total += 1
        else:
            total += 0

        if current_user.sleep == user.sleep:
            total += 1
        else:
            total += 0

        if current_user.cleanliness == user.cleanliness:
            total += 1
        elif (current_user.cleanliness == "clean" and user.cleanliness == "messy") or (current_user.cleanliness == "messy" and user.cleanliness == "clean"):
            total += 0
        else:
            total += 0.5

        # if current_user.price == user.price:
        #     total += 1
        # elif (current_user.price == "$" and user.cleanliness == "$$$") or (current_user.cleanliness == "$$$" and user.cleanliness == "$"):
        #     total += 0
        # else:
        #     total += 0.5

        # if current_user.noiselevel == user.noiselevel:
        #     total += 1
        # elif (current_user.noiselevel == "quiet" and user.noiselevel == "loud") or (current_user.noiselevel == quiet and user.noiselevel == "quiet"):
        #     total += 0
        # else:
        #     total += 0.5

        # if current_user.petfriendly == user.petfriendly:
        #     total += 1
        # else:
        #     total += 0
            
        #total will be a percentage
        total = int((total/3) * 100)

        points.append((user.email, total))

    return points

    #smoker
    # users = users.query.filter(User.smoker==current_user.smoker).all()


""" 
chat functionality
"""
#message sent when you enter the chat room
@socketio.on('joined', namespace='/chat')
def joined(message):
    room = session.get('room')
    join_room(room)
    emit('status', {'msg': session.get('name') + ' has entered the room.'}, room=room)

#sending a message in the chat room
@socketio.on('text', namespace='/chat')
def text(message):
    room = session.get('room')
    emit('message', {'msg': session.get('name') + ': ' + message['msg']}, room=room)

#message sent when you exit the chat room
@socketio.on('left', namespace='/chat')
def left(message):
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