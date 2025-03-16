import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'  # Change this!
    DATABASE = os.environ.get('DATABASE') or 'database.db'  # Database name

    # Bcrypt rounds
    BCRYPT_LOG_ROUNDS = 12

    EMAIL_HEADER_IMAGE_URL = os.environ.get('EMAIL_HEADER_IMAGE_URL') # Add this line