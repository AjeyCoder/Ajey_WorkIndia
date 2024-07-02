from datetime import datetime
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import DOUBLE_PRECISION
import numpy
from psycopg2.extensions import register_adapter, AsIs
from flask_login import UserMixin
from app import db 


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    
    