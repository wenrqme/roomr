import os
import json
from flask import Flask, url_for, flash, render_template, redirect, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
import datetime 
from datetime import datetime, date
import base64
from hashlib import sha512
from werkzeug.security import generate_password_hash, check_password_hash
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

allCities = []
for state in states:
    allCities += [city for city in cities[state]]

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
app.config["SQLALCHEMY_BINDS"] = {
    'history': f"sqlite:///{os.path.join(appdir, 'history.db')}"
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
app.config['UPLOADED_PHOTOS_DEST'] = os.path.join(appdir, 'profile-pictures') # you'll need to create a folder named uploads

"""
User Class & Password Hashing
"""
user_likes = db.Table('likes',
    db.Column('user_id', db.Integer, db.ForeignKey("Users.id"), primary_key=True),
    db.Column('like_id', db.Integer, db.ForeignKey('Users.id'), primary_key=True))

user_dislikes = db.Table('dislikes',
    db.Column('user_id', db.Integer, db.ForeignKey("Users.id"), primary_key=True),
    db.Column('dislike_id', db.Integer, db.ForeignKey('Users.id'), primary_key=True))

user_matches = db.Table('matches',
    db.Column('user_id', db.Integer, db.ForeignKey("Users.id"), primary_key=True),
    db.Column('match_id', db.Integer, db.ForeignKey('Users.id'), primary_key=True))

class User(UserMixin, db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(64), unique=True, index=True, nullable=False)
    fname = db.Column(db.String(32), index=True, nullable=False)
    lname = db.Column(db.String(32), index=True, nullable=False)
    dob = db.Column(db.DateTime, index=True,nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    confirmed = db.Column(db.Boolean(), default=False)

    admin = db.Column(db.Boolean(), default=False)

    profilePicture = db.Column(db.String(64), nullable=True)
    state = db.Column(db.String(32), index=True, nullable=False)
    city = db.Column(db.String(32), index=True, nullable=False)
    gender = db.Column(db.String(6), index=True, nullable=False)
    bio = db.Column(db.String(500), index=True, nullable=True)
    smoker = db.Column(db.String(3), index=True, nullable=False)
    sleep = db.Column(db.String(5), index=True, nullable=False)
    genderPreferences = db.Column(db.String(3), index=True, nullable=False)
    cleanliness = db.Column(db.String(5), index=True, nullable=False)
    price = db.Column(db.String(3), index=True, nullable=False)
    noiselevel = db.Column(db.String(7), index=True, nullable=False)
    petfriendly = db.Column(db.String(3), index=True, nullable=False)
    likes = db.relationship("User", 
                        secondary=user_likes,
                        primaryjoin=(id==user_likes.c.user_id),
                        secondaryjoin=(id==user_likes.c.like_id),
                        backref='liked_by')
    dislikes = db.relationship("User", 
                        secondary=user_dislikes,
                        primaryjoin=(id==user_dislikes.c.user_id),
                        secondaryjoin=(id==user_dislikes.c.dislike_id),
                        backref='disliked_by')
    matches = db.relationship("User", 
                        secondary=user_matches,
                        primaryjoin=(id==user_matches.c.user_id),
                        secondaryjoin=(id==user_matches.c.match_id),
                        backref='matched_by')

    @property
    def password(self):
        raise AttributeError("password is write only")
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        return s.dumps([str(self.id)])

    def confirm(self, token):
        try:
            data = s.loads(token, max_age=3600)
        except Exception as e:
            print(e)
            return False
        if str(data[0]) != str(self.id):
            return False
        self.confirmed = True
        db.session.add(self)
        db.session.commit()
        return True

class History(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    fromID = db.Column(db.Integer, db.ForeignKey('Users.id'))
    toID = db.Column(db.Integer)
    msg = db.Column(db.String(500))
    chatroom = db.Column(db.String(500))
    
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

class DeleteForm(FlaskForm):
    delete = BooleanField("Delete")
    submit = SubmitField('Submit')

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
    city = SelectField("City")
    gender = SelectField("Gender", choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')], validators=[DataRequired()])
    bio = TextAreaField("Bio", validators=[DataRequired()])
    smoker = SelectField("Do you smoke?", choices=[('yes', 'Yes'), ('no', 'No')], validators=[DataRequired()])
    sleepPattern = SelectField("Sleep pattern", choices=[('late', 'Night Owl'), ('early', 'Early Bird')], validators=[DataRequired()])
    cleanliness = SelectField("Cleanliness", choices=[('messy', 'Messy'),('average', 'Average'), ('clean', 'Clean')], validators=[DataRequired()])
    price = SelectField("Price range", choices=[('low', '$'),('average', '$$'), ('high', '$$$')], validators=[DataRequired()])
    noiselevel = SelectField("How loud are you?", choices=[('quiet', 'Quiet'),('average', 'Average'), ('loud', 'Loud')], validators=[DataRequired()])
    petfriendly = SelectField("Pet-friendly?", choices=[('yes', 'Yes'),('no', 'No')], validators=[DataRequired()])
    genderPreferences = SelectField("Gender Preference", choices=[('male', 'Male Only'), ('female', 'Female Only'), ('any', 'Any')], validators=[DataRequired()])
    submit = SubmitField("Submit")
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError("Please use a different email")

class ProfileForm(FlaskForm):
    profilePicture = FileField("Profile Picture", validators=[FileAllowed(images, 'Images only!')])
    state = SelectField("State", choices=[(state, state) for state in states])
    city = SelectField("City")
    gender = SelectField("Gender", choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')], validators=[DataRequired()])
    bio = TextAreaField("Bio", validators=[DataRequired()])
    smoker = SelectField("Do you smoke?", choices=[('yes', 'Yes'), ('no', 'No')], validators=[DataRequired()])
    sleepPattern = SelectField("Sleep pattern", choices=[('late', 'Night Owl'), ('early', 'Early Bird')], validators=[DataRequired()])
    cleanliness = SelectField("Cleanliness", choices=[('messy', 'Messy'),('average', 'Average'), ('clean', 'Clean')], validators=[DataRequired()])
    price = SelectField("Price range", choices=[('low', '$'),('average', '$$'), ('high', '$$$')], validators=[DataRequired()])
    noiselevel = SelectField("How loud are you?", choices=[('quiet', 'Quiet'),('average', 'Average'), ('loud', 'Loud')], validators=[DataRequired()])
    petfriendly = SelectField("Pet-friendly?", choices=[('yes', 'Yes'),('no', 'No')], validators=[DataRequired()])
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
        for user in users:
            print(user.email, points[0][0])
            if user.email == points[0][0]:
                users = [user]
                break            
        points = dict(points)
        return render_template("home.html", users = users, points = points)
    else:
        print("else home")
        return render_template("home.html")

#sign-up page
@app.route("/signup", methods=["GET","POST"])
def signup():
    fname, lname, email, dob, password = None, None, None, None, None
    prefill = {'state': 'Alabama'}
    form = SignupForm(data=prefill)
    form.city.choices = [(city, city) for city in cities[form.state.data]]
    print(form.city.choices)
    print("city:", form.city.data)
    if form.validate_on_submit():
        fname = form.fname.data
        lname = form.lname.data
        email = form.email.data
        dob = form.dob.data
        userPassword = form.password.data
        if form.profilePicture.data != None:
            filename = images.save(form.profilePicture.data)
            file_url = images.url(filename)
            profilePicture = file_url
            # profilePicture = images.path(filename)
        else:
            profilePicture = url_for('static', filename="generic-profile-picture.jpg")
        state = form.state.data
        city = form.city.data
        gender = form.gender.data
        bio = form.bio.data
        smoker = form.smoker.data
        sleepPattern = form.sleepPattern.data
        genderPreferences = form.genderPreferences.data
        cleanliness = form.cleanliness.data
        price = form.price.data
        noiselevel = form.noiselevel.data
        petfriendly = form.petfriendly.data
        #add profilePicture=profilePicture to user
        user = User(email= email, fname= fname, lname=lname, dob= dob, password=userPassword, profilePicture=profilePicture, \
            state=state, city=city, cleanliness=cleanliness, gender=gender, \
            bio = bio, smoker=smoker, sleep=sleepPattern, genderPreferences = genderPreferences, \
            price=price, noiselevel=noiselevel, petfriendly=petfriendly)
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
        # flash(form.errors)
    return render_template("signup.html", form=form)

class PasswordForm(FlaskForm):
    password = PasswordField("New password", validators=[DataRequired(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm new password', validators=[DataRequired()])
    old_password = PasswordField('Old password', validators=[DataRequired()])
    submit = SubmitField("Submit")

@app.route("/resetpassword", methods=["GET","POST"])
@login_required
def resetPassword():
    user = current_user
    form = PasswordForm()
    if form.validate_on_submit():
        print("validated")
        if user.verify_password(form.old_password.data):
            print("user verified")
            user.password = form.password.data
            db.session.add(user)
            db.session.commit()
            flash('Password updated!')
            next = request.args.get("next")
            if next is None or not next.startswith("/"):
                next = url_for("user")
            return redirect(next)
        else:
            print("user invalid pass")
            flash("Old password is incorrect.")
        return render_template("reset.html", form=form)
    elif request.method=="POST": 
        print("not validated")
        flash('Some information is incorrect')
    # flash(form.errors)
    return render_template("reset.html", form=form)

@app.route("/resend", methods=["GET", "POST"])
@login_required
def resendVerification():
    token = current_user.generate_confirmation_token()
    app.config['SECRET_KEY'] = token
    print(f"{app.config['SECRET_KEY']} is the token")
    send_email(current_user.email, 'roomr Email Verification',
                "email_Auth.txt", current_user, token=token)
    return render_template('signupresp.html', user=current_user)

class getEmailForm(FlaskForm):
    email = StringField("Email to send reset link", validators=[DataRequired(), Email()])
    submit = SubmitField("Submit")

#forgot your password
@app.route("/fyp", methods=["GET", "POST"])
def get_reset_email():
    form = getEmailForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            print("form validated and submitted!")
            token = user.generate_confirmation_token()
            app.config['SECRET_KEY'] = token
            print(f"{app.config['SECRET_KEY']} is the token")
            send_password_reset_email('roomr Email Password Reset', email=user.email, token=token)
            print("email sent!")
            flash("An email has been sent!")
        else:
            flash("That is not a valid email!")
    return render_template("fyp.html", form=form)
    
class ForgotPasswordForm(FlaskForm):
    password = PasswordField("New password", validators=[DataRequired(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm new password', validators=[DataRequired()])
    submit = SubmitField("Submit")

@app.route("/forgot/<string:token>/<string:email>", methods=["GET", "POST"])
def forgot_password(token, email):
    form = ForgotPasswordForm()
    user = User.query.filter_by(email=email).first()
    if user:
        print("User found")
        if form.validate_on_submit():
            user.password = form.password.data
            db.session.add(user)
            db.session.commit()
            flash('Password Reset!')
            next = request.args.get("next")
            if next is None or not next.startswith("/"):
                next = url_for("login")
            return redirect(next)
        elif request.method == "POST":
            flash("Something is incorrect")
    elif request.method == "POST":
        flash('That is not a valid email!')
        # flash(form.error)
    return render_template("reset_forgot.html", form=form, token = token)
        

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
                next = url_for("home")
            return redirect(next)
        flash("Invalid Username or password.")
    return render_template("login.html", form=form)

def send_email(to, subject, template, User, token):
    me = app.config["MAIL_USERNAME"]
    to = User.email
    msg = Message(subject, sender=app.config["MAIL_USERNAME"], recipients=[
                  to])
    with open(os.getcwd() + "/templates/" + template) as f:
        msg.body = f.read()
    msg.body += url_for('confirm', token=token, _external=True)
    mail.send(msg)

def send_password_reset_email(subject, email, token):
    me = app.config["MAIL_USERNAME"]
    to = email
    msg = Message(subject, sender=app.config["MAIL_USERNAME"], recipients=[to])
    msg.body = ""
    msg.body += "Hello " + "!\n\n" + "Click this link to reset your password " + "\n"
    msg.body += url_for('forgot_password', email=email, token=token, _external=True)
    mail.send(msg) 


def send_match_email(subject, User, matchedUser):
    me = app.config["MAIL_USERNAME"]
    to = User.email
    msg = Message(subject, sender=app.config["MAIL_USERNAME"], recipients=[
                  to])
    msg.body = ""
    msg.body += "Hello " + User.fname + "!\n\n" + "You matched with " + matchedUser.fname + "! Check you matches page to chat!\n" 
    msg.body += url_for('matches', _external=True)
    mail.send(msg)

#logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("you have been logged out")
    return redirect(url_for("login"))

@app.route("/user/delete", methods=["GET","POST"])
@login_required
def Delete():
    form = DeleteForm()
    if form.validate_on_submit():
        print("delete? " + current_user.fname)
        if form.delete.data:
            print("Deleting...")
            db.session.delete(current_user)
            db.session.commit()
            flash("Your account has been successfully deleted", "success")
            return redirect(url_for("login"))
    else:
        print("else")
    return render_template("Delete.html", form=form)
    
#edit profile page
@app.route("/user/edit", methods=["GET","POST"])
@login_required
def editProfile():
    profilePicture, state, city, gender, bio, smoker, sleepPattern, cleanliness, genderPreferences = None, None, None, None, None, None, None, None, None
    user = current_user
    prefill = {'state': str(user.state), 'city': str(user.city), 'gender':str(user.gender), 'bio':str(user.bio), 'smoker':str(user.smoker), 'sleepPattern':str(user.sleep), 'cleanliness':str(user.cleanliness), 'genderPreferences':str(user.genderPreferences), 'noiselevel':str(user.noiselevel), 'price':str(user.price), 'petfriendly':str(user.petfriendly)}
    form = ProfileForm(data=prefill)
    form.city.choices = [(city, city) for city in cities[str(user.state)]]
    if form.validate_on_submit and request.method=="POST":
        if form.profilePicture.data != None:
            print(form.profilePicture.data)
            filename = images.save(form.profilePicture.data)
            file_url = images.url(filename)
            user.profilePicture = file_url
        user.state = form.state.data    
        user.city = form.city.data
        user.gender = form.gender.data
        user.bio = form.bio.data
        user.smoker = form.smoker.data
        user.sleep = form.sleepPattern.data
        user.cleanliness = form.cleanliness.data
        user.genderPreferences = form.genderPreferences.data
        user.price = form.price.data
        user.noiselevel = form.noiselevel.data
        user.petfriendly = form.petfriendly.data
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

@app.route("/admin", methods=["GET"])
@login_required
def admin():
    if current_user.admin == True:
        users = User.query.all()
        return render_template("admin.html", users=users)
    return redirect(url_for("home"))

@app.route("/admin/user/<int:uid>", methods=["GET"])
@login_required
def adminViewAccount(uid):
    if current_user.admin == True:
        user = User.query.filter_by(id=uid).first()
        messages = [chat for chat in History.query.filter_by(fromID=user.id).all()]
        return render_template("view_user.html", user=user, messages=messages)
    else: return redirect(url_for("home"))

@app.route("/admin/user/<int:uid>/delete", methods=["GET","POST"])
@login_required
def adminDelete(uid):
    user = User.query.filter_by(id=uid).first()
    form = DeleteForm()
    if form.validate_on_submit():
        print("delete? " + user.fname)
        if form.delete.data:
            print("Deleting...")
            db.session.delete(user)
            db.session.commit()
            flash("Your account has been successfully deleted", "success")
            return redirect(url_for("admin"))
    else:
        print("else")
    return render_template("Delete.html", form=form)

#private chat room page
@app.route('/privatechat/<email>')
@login_required
def privatechat(email):
    print("private chat function")
    user = User.query.filter_by(email=email).first()
    room = " ".join(sorted([user.email, current_user.email]))
    name = current_user.fname
    session['room'] = room
    session['name'] = name
    session['fromID'] = current_user.id
    session['toID'] = user.id
    room = session.get('room', '')
    name = session.get('name', '')
    messages = History.query.filter_by(chatroom=room).all()
    messages = [f"{User.query.filter_by(id=msg.fromID).first().fname}: {msg.msg}" for msg in messages]
    print(messages)
    return render_template('privatechat.html', user=user, name=name, room=room, messages=messages)

#login page to enter a chatroom
@app.route('/matches', methods=["GET", "POST"])
@login_required
def matches():
    form = ChatForm()
    your_rooms = [chat.chatroom for chat in History.query.filter_by(fromID=current_user.id).all()]
    additional = [chat.chatroom for chat in History.query.filter_by(toID=current_user.id).all()]
    your_rooms.extend(additional)
    unique_rooms = []
    for i in your_rooms:
        if i not in unique_rooms:
            unique_rooms.append(i)
    print(unique_rooms)
    modified_unique_rooms = []
    for room in unique_rooms:
        word = room.split(" ")
        for w in word:
            if w != current_user.email:
                modified_unique_rooms.append(w)
    print(modified_unique_rooms)
    #modified_unique_rooms shows the email of the user who is not the current_user
    return render_template('matches.html', form=form, user=current_user, chatroom=modified_unique_rooms)

@app.route("/confirm/<string:token>")
@login_required
def confirm(token):
    if current_user.confirmed:
        print("already confirmed")
    elif current_user.confirm(token):
        print("confirming...")
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
        users = User.query.filter(or_(User.genderPreferences==current_user.gender, User.genderPreferences=='any'), User.state==current_user.state, User.city==current_user.city, User.id!=current_user.id).all()
    elif current_user.genderPreferences == "male":
        users = User.query.filter(or_(User.gender=="male", User.gender=="other"), or_(User.genderPreferences==current_user.gender, User.genderPreferences=="any"), User.state==current_user.state, User.city==current_user.city, User.id!=current_user.id).all()
    elif current_user.genderPreferences == "female":
        users = User.query.filter(or_(User.gender=="female", User.gender=="other"), or_(User.genderPreferences==current_user.gender, User.genderPreferences=="any"), User.state==current_user.state, User.city==current_user.city, User.id!=current_user.id).all()
    show_users = []
    print(users)
    for user in users:
        if (not user in current_user.likes) and (not user in current_user.dislikes):
            show_users.append(user)
    print(show_users)
    return show_users

@app.route('/like/<int:uid>', methods=["GET", "POST"])
def like(uid):
    print(uid)
    otherUser = User.query.filter_by(id=uid).first()
    current_user.likes.append(otherUser)
    print(current_user.likes)
    if current_user in otherUser.likes:
        if current_user.confirmed: send_match_email("roomr - New Match", current_user, otherUser)
        if otherUser.confirmed: send_match_email("roomr - New Match", otherUser, current_user)
        current_user.matches.append(otherUser)
        otherUser.matches.append(current_user)
    db.session.add(current_user)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/dislike/<int:uid>', methods=["GET", "POST"])
def dislike(uid):
    print(uid)
    otherUser = User.query.filter_by(id=uid).first()
    current_user.dislikes.append(otherUser)
    db.session.add(current_user)
    db.session.commit()
    print(current_user.dislikes)
    return redirect(url_for('home'))

@app.route('/unmatch/<int:uid>', methods=["GET", "POST"])
def unmatch(uid):
    otherUser = User.query.filter_by(id=uid).first()
    current_user.matches.remove(otherUser)
    otherUser.matches.remove(current_user)
    db.session.add(current_user)
    db.session.commit()
    return redirect(url_for('matches'))

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
        if current_user.price == user.price:
            total += 1
        elif (current_user.price == "$" and user.price == "$$$") or (current_user.price == "$$$" and user.price == "$"):
            total += 0
        else:
            total += 0.5
        if current_user.noiselevel == user.noiselevel:
            total += 1
        elif (current_user.noiselevel == "quiet" and user.noiselevel == "loud") or (current_user.noiselevel == "quiet" and user.noiselevel == "quiet"):
            total += 0
        else:
            total += 0.5
        if current_user.petfriendly == user.petfriendly:
            total += 1
        else:
            total += 0
        #total will be a percentage
        total = int((total/6) * 100)
        points.append((user.email, total))
    newpoints = sorted(points, key = lambda x: x[1], reverse=True)
    print("sorted: ", newpoints)
    return newpoints

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
    toID = session.get('toID')
    fromID = session.get('fromID')
    temp_message = History(fromID=fromID, toID=toID, msg=message['msg'], chatroom=room)
    db.session.add(temp_message)    
    db.session.commit()
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
    app.run(host='127.0.0.1', port=8080, debug=True) #, ssl_context=('cert.pem', 'key.pem'))
    socketio.run(app)