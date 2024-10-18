from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Initialize the database and other extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Initialize login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Import the User model here after initializing the app and db
from app.models import User

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from app import routes
