from flask import Blueprint , render_template ,url_for, request, redirect , session 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required ,current_user
from passlib.hash import scrypt
from app import db 
from flask_cors import cross_origin 
from flask import Flask, request, jsonify, current_app , session ,make_response
from flask_sqlalchemy import SQLAlchemy
from model import User
import uuid 
from flask_jwt_extended import create_access_token , jwt_required , get_jwt_identity , JWTManager


auth = Blueprint('auth', __name__)

@auth.route('/signup' , methods = ['POST', 'OPTIONS'])
def signup( ):
    if request.method == 'POST': 
       data = request.get_json()
       if  "email" not in data or "username" not in data or "password" not in data: 
            resp2 = make_response({'error': 'Invalid request'})
            return resp2,400
       #Here in the bellow case all of this data will be in a database which stored registered users 
       #Here we see that in the bellow case email is the Primary key
       id = uuid.uuid1()
       email = data["email"]
       name = data["username"]
       password = data["password"]
       user = User.query.filter_by(email=email).first()
       
       #If a user exists then there is no point in registering so we send the bellow response 
       if user:
           resp3 = make_response({'error': 'User already exists'} )
           return resp3 , 409
       #This is the case where we use a library to hash the password that we have 
       hashed_password = scrypt.hash(password)
       new_user = User(email=email, name=name, password=hashed_password , id = id.node)
       
       try:
            db.session.add(new_user)
            db.session.commit() 
            resp= { 
            'message' : 'Account successfully created',
            'user_id' : id.node
            }
            
            return resp,200 
       except Exception as e:
            db.session.rollback()  
            resp5 = make_response({'error': 'Registration failed'})
            return resp5,500
        
@auth.route('/login' , methods = ['POST','OPTIONS'])
def login():
    if request.method == 'POST':
      data = request.get_json()
      if not data or "email" not in data or "password" not in data:
            resp6 = make_response({'error': 'Registration failed'}, )
            return resp6,400
      email = data["email"]
      password = data["password"]
      user = User.query.filter_by(email=email).first() 
      
      if user and scrypt.verify(password, user.password):
         login_user(user , remember = True)
         if current_user.is_authenticated:
            access_token = create_access_token(identity = user.email)
            resp= { 
              'message' : 'Login Sucessful',
              'user_id' :  str(user.user_id), 
              'access-token':access_token
            }
            resp1 = make_response(resp)
            return resp1,200
         else:
             resp8 = make_response({'message' : 'Incorrect Username/Password provided. Please retry'})
             return resp8,401
        

    