from flask_login import current_user
from app import BlogPost
from flask import Flask, redirect, render_template, request, redirect, g
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(app)

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    author = db.Column(db.String(100))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return 'Blog post ' + str(self.id)

all_posts = [
    {
        "title": "Post 1",
        "content": "This is the content of post 1. Lalalalala",
        "author": "Ulaş Gülhan"
    },
    {
        "title": "Post 2",
        "content": "This is the content of post 2. Lalalalala"
    }
]

@app.route('/test', methods=['GET', 'POST'])
def posts():
    if request.method == 'POST':
        post_content = request.form['content']
        post_author = request.form['author']
        new_post = BlogPost(content=post_content, author=post_author)
        db.session.add(new_post)
        db.session.commit()
        return redirect('/test')
    else:
        all_posts = BlogPost.query.order_by(BlogPost.date_posted).all()
        return render_template('test.html', posts=all_posts)

@app.route('/posts/delete/<int:id>')
def delete(id):
    post = BlogPost.query.get_or_404(id)
    db.session.delete(post)
    db.session.commit()
    return redirect('/posts')

@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):

    post = BlogPost.query.get_or_404(id)

    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        post.author = request.form['author']
        db.session.commit()
        return redirect('/posts')
    else:
        return render_template('edit.html', post=post)

if __name__ == "__main__":
    app.run(debug=True)