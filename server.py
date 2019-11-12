import os
from flask import Flask, url_for, flash, render_template, redirect, request
from flask_sqlalchemy import SQLAlchemy
import datetime 
from datetime import datetime
import base64
# import bcrypt 
from hashlib import sha512
from werkzeug import generate_password_hash, check_password_hash
# from cryptography.fernet import Ferne
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, DateField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, ValidationError
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user



app = Flask(__name__)
app.config["SECRET_KEY"] = "oEHYBreJ2QSefBdUhD19PkxC"
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=["GET"])
def home():
    return render_template("home.html")
    #need links to login or create an account


# 
# Database Stuff
#
appdir = os.path.abspath(os.path.dirname(__file__))

app.config["SQLALCHEMY_DATABASE_URI"] = \
	f"sqlite:///{os.path.join(appdir, 'library.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)



# """
# User Class & Password Hashing
# """
class User(UserMixin, db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(64), unique=True, index=True, nullable=False)
    fname = db.Column(db.String(32), index=True, nullable=False)
    lname = db.Column(db.String(32), index=True, nullable=False)
    dob = db.Column(db.DateTime, index=True,nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    @property
    def password(self):
        raise AttributeError("password is write only")
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

db.create_all()



# """
# Login and Signup

# """

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Submit")

class SignupForm(FlaskForm):
    fname = StringField("First Name", validators=[DataRequired()])
    lname = StringField("Last Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    dob = DateField("Date of Birth", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError("Please use a different email")

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

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("you have been logged out")
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET","POST"])
def signup():
    fname, lname, email, dob, password = None, None, None, None, None
    form = SignupForm()
    print(form.validate_on_submit())
    if form.validate_on_submit():
        fname = form.fname.data
        form.fname.data = None 
        lname = form.lname.data
        form.lname.data = None
        email = form.email.data
        form.email.data = None
        dob = form.dob.data
        form.dob.data = None
        userPassword = form.password.data
        form.password.data = None
        user = User(email= email, fname= fname, lname=lname, dob= dob, password=userPassword)
        db.session.add(user)
        db.session.commit()
        print("form validated and submitted!")
        return render_template('signupresp.html', user=user)
    else: 
        print("not validated")
        flash('Some information is incorrect')
    return render_template("signup.html", form=form)


@app.route("/user", methods=["GET"])
@login_required
def user():
    return render_template("user.html")



if __name__ == "__main__": 
    app.run()
