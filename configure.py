import os

SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://user:password@db:5432/mydatabase')
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = os.getenv('SECRET_KEY', 'my_secret_key')  
DEBUG = os.getenv('DEBUG', False)
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', '296056700617113930088248183538080088332')