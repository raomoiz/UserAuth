from flask import Flask, render_template, redirect, url_for, request, flash
from flask_pymongo import PyMongo 
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb+srv://userAuth:7QS6pPjaznw1I7CX@userauth.ktwnotc.mongodb.net/users'
app.config['SECRET_KEY'] = '7QS6pPjaznw1I7CX'

mongo = PyMongo(app) 
bcrypt = Bcrypt(app)  
login_manager = LoginManager(app)  
login_manager.login_view = 'login' 

class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id


@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({'_id': user_id})
    if user:
        return User(user_id=user["_id"])
    return None


@app.route('/')
def index():
    return render_template('home.html',msg='')

@app.route('/register',methods=['POST','GET'])
def register():
    if request.method == 'POST':
        userEmail = request.form.get('userEmail')
        password = request.form.get('password')
        user = mongo.db.users.find_one({'userEmail': userEmail})
        if not user:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            mongo.db.users.insert_one({'userEmail': userEmail, 'password': hashed_password})
            flash('Registration successful!', 'success')
        else:
            flash('Email already exists', 'danger')
            return render_template('register.html',msg='Email already exists')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST']) 
def login():
    print(current_user)
    if request.method == 'POST':
        userEmail = request.form.get('userEmail')
        password = request.form.get('password')
        user = mongo.db.users.find_one({'userEmail': userEmail})
    
        if user and bcrypt.check_password_hash(user['password'], password):
            login_user(User(user["_id"]))
            flash('Login successful!', 'success')
            user_id = load_user(current_user.id).id
            user = mongo.db.users.find_one({'_id': user_id})['userEmail'].split("@")[0]
            return render_template('home.html', userEmail=user)
        else:

            flash('Invalid username or password', 'danger')
            return render_template('login.html', userEmail=userEmail,msg = 'Invalid username or password')
    return render_template('login.html',msg='')
@app.route('/logout')
@login_required  
def logout():
    logout_user()
    flash('You have been logged out.', 'success') 
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html',username = load_user(current_user.id).userEmail) 

if __name__ == '__main__':
    app.run(debug=True) 