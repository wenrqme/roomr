# CSC210 Final Project - roomr
roommate finder app

# Collaborators: 
- Brandon Toops
- Claire MacCormick 
- Melissa Wen 
- Aiden Siegle 
- Prinaya Choubey 


What is roomr? It’s like Tinder but for roommates! Users can sign up, match up and chat with potential roommates based on the preferences they choose.

We have fulfilled all the main requirements for the project:
- HTML and CSS are used for the layout of the website
- Python-Flask is used to create and run the server for the website
- Jinja2 templates are used to display the forms and pictures
- WTF-Forms are used to take information from the user, allow them to log into their profile, edit their information, and delete their account
- Flask-SQLAlchemy is used to create a database that stores a user’s information and preferences in tables
- Flask-Login is used to let the user log into their account
- Passwords are appropriately hashed in the database for all users 
- The app is run over HTTPS (using a self-signed certificate. On our cloud hosted site we have a real certificate from Let's Encrypt)
This project also serves a reasonable purpose, which is to help facilitate the process of finding a roommate with whom you are the most compatible. 

The additional features we implemented are:
- Hosting the website on the cloud using AWS (www.roomr-app.me)
- Live chat functionality between users
- People can delete their accounts
- Email verification on account creation
- Email notifications for when two users match with each other
- Password reset
- Forgot password
- Admin accounts
- Blocking users

Some features from the proposal that we didn't implement are:
- OAuth
- Reporting users
