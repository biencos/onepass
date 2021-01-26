import os
import logging

from flask import render_template
from dotenv import load_dotenv

from app import app


load_dotenv()
app.secret_key = os.getenv("SECRET_KEY")
logging.basicConfig(level=logging.INFO)


# HOME
@ app.route('/')
def load_home():
    return render_template("home.html")
