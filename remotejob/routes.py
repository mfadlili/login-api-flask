from remotejob import app, db
from remotejob.models import User
from flask_login import login_user,login_required,logout_user, current_user
from flask import jsonify, request

@app.route('/')
def home():
    return jsonify({"message":"Please Login"})

@app.route('/welcome')
@login_required
def welcome_user():
    return jsonify({"message":"Welcome!!"})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"message":"Logout Success!!"})

@app.route('/login', methods=['POST'])
def login():

    if request.method=="POST":
        email = request.get_json(force=True)["email"]
        password = request.get_json(force=True)["password"]
        # Grab the user from our User Models table
        user = User.query.filter_by(email=email).first()

        if user.check_password(password) and user is not None:

            login_user(user)

            return jsonify({"status":200, "message":"Logged in successfully."})
        
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