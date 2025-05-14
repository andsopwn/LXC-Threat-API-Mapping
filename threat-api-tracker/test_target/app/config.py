import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "top-secret-key")
    DEBUG = False
