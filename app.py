from datetime import datetime
import os
from marshmallow import fields, Schema
from flask import Flask, g, redirect, render_template, url_for, jsonify, request
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, current_user, login_user, LoginManager, login_required, logout_user
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, length
from sqlalchemy.orm import validates
import re
from flask_migrate import Migrate


BASE_DIR = os.path.dirname(__file__)
app = Flask(__name__)
db = SQLAlchemy(app)
bycrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///authentication.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
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
    # posts = db.relationship('BlogPost', backref='user')


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

class BlogPost(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    author = db.Column(db.String(100))
    comment = db.Column(db.String)
    points = db.Column(db.Integer, nullable=True)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return 'Blog post ' + str(self.id)

class BlogComment(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text)
    comment_author = db.Column(db.String(100))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

class CommentSchema(Schema):
    id = fields.Integer(dump_only=True)
    comment = fields.String()
    comment_author = fields.String()

class UserSchema(Schema):
    id = fields.Integer(dump_only=True)
    email = fields.Email()
    username = fields.String()

class PostSchema(Schema):
    id = fields.Integer(dump_only=True)
    content = fields.String()
    author = fields.String()
    comment = fields.String()
    point = fields.Integer()
    
comment_schema = CommentSchema(many=True)

user_schema = UserSchema(many=True)

post_schema = PostSchema(many=True)


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

# class PostForm(FlaskForm):
#     content = StringField(validators=[InputRequired(), length(min=1, max=200)], render_kw={"placeholder": "What do you think?"})

#     submit = SubmitField("Post")

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
    if request.method == 'POST':
        g.user = current_user.username
        post_content = request.form['content']
        post_author = g.user
        new_post = BlogPost(content=post_content, author=post_author)
        db.session.add(new_post)
        db.session.commit()
        return redirect('dashboard')
    else:
        all_posts = BlogPost.query.order_by(BlogPost.date_posted).all()
        return render_template('dashboard.html', posts=all_posts)


@app.route('/dashboard/comment/<int:id>', methods=['GET', 'POST'])
@login_required
def comment(id):
    comment = BlogPost.query.get_or_404(id)
    if request.method == 'POST':
        g.user = current_user.username
        comment_content = request.form['comment']
        comment_author = g.user
        new_comment = BlogComment(comment=comment_content, comment_author=comment_author)
        db.session.add(new_comment)
        db.session.commit()
        return redirect('/dashboard')
    else:
        post = BlogPost.query.filter_by(id=id).first()
        return render_template('comment.html', comment=comment, post=post)

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

@app.route('/send', methods=['GET'])
def fed():
    post = BlogPost.query.all()
    data = post_schema.dump(post)
    return jsonify(data)

@app.route('/comments', methods=['GET'])
def comments():
    post = BlogComment.query.all()
    data = post_schema.dump(post)
    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True)
