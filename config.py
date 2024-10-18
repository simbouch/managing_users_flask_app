import os
from dotenv import load_dotenv

# Define the base directory
basedir = os.path.abspath(os.path.dirname(__file__))

# Load environment variables from the .env file
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')  # Fetch SECRET_KEY from the environment or .env file
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
