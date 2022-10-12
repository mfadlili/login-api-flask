from remotejob import app, db
from remotejob.models import User, ExpToken
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
    
        current_token = ExpToken.query.filter_by(token_code=token).first()
        
        if current_token is None:
            return jsonify({'message': 'token not available'})
        elif current_token.exp < datetime.datetime.utcnow():
            db.session.delete(current_token)
            db.session.commit()
            return jsonify({'message': 'token is expired'})
        else:
            current_user = User.query.get(current_token.user_id)
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
def logout(current_user):

    token_code = request.headers['x-access-tokens']
    delete_token = ExpToken.query.filter_by(token_code = token_code).first()
    db.session.delete(delete_token)
    db.session.commit()

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
            check_token = ExpToken.query.filter_by(user_id=user.id).first()

            if check_token is None:
                exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=45)
                token = jwt.encode({'public_id' : user.id, 'exp' : exp}, app.config['SECRET_KEY'], "HS256")
                add_token = ExpToken(token, user.id, exp)
                db.session.add(add_token)
                db.session.commit()

                return jsonify({"status":200, "message":"Logged in successfully.",
                "token":token
                })
            
            else:
                token = check_token.token_code
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

