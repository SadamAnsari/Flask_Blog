from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from forms import LoginForm, RegisterForm

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myblog.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'S3CR3TK3Y!'
bootstrap = Bootstrap(app)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    posts = db.relationship('BlogPost', backref='user', lazy=True)


class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    sub_title = db.Column(db.String(50))
    author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime)
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('index'))
            else:
                error = "Invalid username or password"
    return render_template('login.html', form=form, error=error)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    error = None
    if request.method == "POST":
        if form.validate_on_submit():
            if User.query.filter_by(username=form.username.data).first():
                error = "Username ({}) already exists.".format(form.username.data)
            elif User.query.filter_by(email=form.email.data).first():
                error = "Email ({}) already exists.".format(form.email.data)
            else:
                hashed_password = generate_password_hash(form.password.data, method='sha256')
                new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for('index'))
    return render_template('signup.html', form=form, error=error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/')
def index():
    posts = BlogPost.query.order_by(BlogPost.date_posted.desc()).all()
    if current_user.is_authenticated:
        # print("current_user", current_user.__dict__)
        return render_template("dashboard.html", user=current_user, posts=posts)
    else:
        return render_template("index.html", posts=posts)


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/post/<int:post_id>')
def post(post_id):
    post_obj = BlogPost.query.filter_by(id=post_id).one()
    return render_template("post.html", post=post_obj)


@app.route('/contact')
def contact():
    return render_template("contact.html")


@app.route('/add')
@login_required
def add():
    return render_template("add.html", error=None)


@app.route('/addpost', methods=["POST"])
@login_required
def addpost():
    title = request.form['title']
    sub_title = request.form['sub_title']
    author = request.form['author']
    content = request.form['content']
    post_obj = BlogPost(title=title, sub_title=sub_title, author=author, content=content,
                        date_posted=datetime.now(), user_id=current_user.id)
    db.session.add(post_obj)
    db.session.commit()
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(port=80, debug=True)