import os
from marshmallow import fields, validate, Schema
from flask import Flask, redirect, render_template, url_for, jsonify
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, length, ValidationError
from sqlalchemy.orm import validates
import re

BASE_DIR = os.path.dirname(__file__)
app = Flask(__name__)
db = SQLAlchemy(app)
bycrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///authentication.db'
app.config['SECRET_KEY'] = 'secretkey'
api = Api(app)
ma = Marshmallow(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "Login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#database oluşturma
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(40), nullable=False, unique=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    def __init__(self, email, username, password):
        self.email = email
        self.username = username
        self.password = password

    @validates('email')
    def validate_email(self, key, email):
        if not email:
            raise AssertionError('No email provided')
        if not re.match("[^@]+@[^@]+\.[^@]+", email):
            raise AssertionError('Provided email is not an email address')
        return email


class UserSchema(Schema):
    id = fields.Integer(dump_only=True)
    email = fields.Email()
    username = fields.String()


user_schema = UserSchema(many=True)


#Kayıt formu oluşturma
class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), length(min=6, max=20)], render_kw={"placeholder": "Email"})
    username = StringField(validators=[InputRequired(), length(min=3, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), length(min=3, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")


#Giriş formu oluşturma
class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), length(min=6, max=40)], render_kw={"placeholder": "Email"})
    username = StringField(validators=[InputRequired(), length(min=3, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), length(min=3, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

#Sayfalar arası bağlantılar
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bycrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect('login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bycrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        db.session.close()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/users', methods=['GET'])
def get():
    users = User.query.all()
    data = user_schema.dump(users)
    return jsonify(data)

# @app.route('/users/<id>', methods=['GET'])
# def get_id(id):
#     return jsonify({'id': User[id]})

# @app.route('/users/<id>', methods=['GET'])
# def get_users(id):
#     res = json.dumps(User)
#     users = User.query.get_or_404(id)
#     return jsonify({'id': users.id, 'email': users.email, 'username': users.username, 'password': users.password} )

# class meta(metaclass=User):
#     def __init__(self):
#         pass

# class get(meta, Resource):
#     def get(self):
#         return

# api.add_resource(get, '/')

#encoding="utf-8"

if __name__ == "__main__":
    app.run(debug=True)
