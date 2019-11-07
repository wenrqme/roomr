import os
from flask import Flask, url_for, flash, render_template
from flask_sqlalchemy import SQLAlchemy
import datetime 
from datetime import datetime
import base64
# import bcrypt 
from hashlib import sha512
# from cryptography.fernet import Ferne
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, DateField, PasswordField
from wtforms.validators import DataRequired, Email
from flask_login import LoginManager, login_user, UserMixin


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
    
# """
# Login and Signup

# """

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

class SignupForm(FlaskForm):
    fname = StringField("First Name", validators=[DataRequired()])
    lname = StringField("Last Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    dob = DateField("Date of Birth", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

@app.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and \
                user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get("next")
            if next is None or not next.startswith("/"):
                next = url_for("index")
            return redirect(next)
        flash("Invalid Username or password.")
    return render_template("login.html", form=form)

@app.route("/signup", methods=["GET","POST"])
def signup():
    form = SignupForm()
    return render_template("signup.html", form=form)

# """
# User Password Hashin

# """
# class User(UserMixin, db.Model):
#     __tablename__ = "Users"
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(64), unique = True, index = True)
#     username = db.Column(db.String(64), unique = True, index = True)
#     password_hash = db.Column(db.String(128))
#     role_id = db.Column(db.Integer, db.ForeignKey("roles.id"))
#     @property
#     def password(self):
#         raise AttributeError("password is write only")
    
#     @password.setter
#     def password(self, password):
#         self.password_hash = generate_password_hash(password)
    
#     def verify_password(self, password):
#         return check_password_hash(self.password_hash, password)

if __name__ == "__main__": 
    app.run()