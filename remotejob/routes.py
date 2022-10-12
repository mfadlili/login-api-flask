from remotejob import app, db
from remotejob.models import User
from flask_login import login_user,login_required,logout_user, current_user
from flask import jsonify, request
import jwt
from functools import wraps
import datetime

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token = None
       if 'x-access-tokens' in request.headers:
           token = request.headers['x-access-tokens']
 
       if not token:
           return jsonify({'message': 'a valid token is missing'})
       try:
           data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
           current_user = User.query.get(data['public_id'])
       except:
           return jsonify({'message': 'token is invalid'})
 
       return f(current_user, *args, **kwargs)
   return decorator

@app.route('/')
def home():
    return jsonify({"message":"Please Login"})

@app.route('/welcome')
@token_required
def welcome_user(current_user):
    user = current_user
    return jsonify({"message":f"Welcome {user.username} !!"})

@app.route('/logout')
@token_required
def logout():
    logout_user(current_user)
    return jsonify({"message":"Logout Success!!"})

@app.route('/login', methods=['POST'])
def login():

    if request.method=="POST":
        email = request.get_json(force=True)["email"]
        password = request.get_json(force=True)["password"]
        if not email or not password:
            return jsonify({"message":"Couldn't find email or password"})
        # Grab the user from our User Models table
        user = User.query.filter_by(email=email).first()

        if user.check_password(password) and user is not None:

            token = jwt.encode({'public_id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")

            return jsonify({"status":200, "message":"Logged in successfully.",
            "token":token
            })
        
        else:
            return jsonify({"status":401, "message": "Can't login"})

@app.route('/register', methods=['POST'])
def register():
    if request.method=="POST":
        email = request.get_json(force=True)["email"]
        username = request.get_json(force=True)["username"]
        password = request.get_json(force=True)["password"]
        user = User(email=email,
                    username=username,
                    password=password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"status":200, "message":'Thanks for registering! Now you can login!'})