
import os
from flask import Flask, render_template, redirect, url_for, request, flash, session
from requests_oauthlib import OAuth2Session
import requests
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from forms import LoginForm, RegisterForm
from api_token import CLIENT_ID, CLIENT_SECRET

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myblog.sqlite3'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'S3CR3TK3Y!'
app.config['GOOGLE_CLIENT_ID'] = CLIENT_ID
app.config['GOOGLE_CLIENT_SECRET'] = CLIENT_SECRET
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
bootstrap = Bootstrap(app)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    posts = db.relationship('BlogPost', backref='user', lazy=True)
    oauth_id = db.relationship("AuthUser", uselist=False, back_populates="User")


class AuthUser(db.Model):
    __tablename__ = "auth_users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(200))
    active = db.Column(db.Boolean, default=False)
    tokens = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow())
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    user = db.relationship("User", back_populates="AuthUser")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"

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


def login_oauth_user():
    user_info = session.get('user')
    if user_info:
        try:
            name = user_info.get('name')
            email = user_info.get('email')
            password = 'GoogleUserLogin1234'
            user_id = user_info.get('id')
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = User(username=name, email=email, password=hashed_password, oauth_id=user_id)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('index'))
        except IntegrityError as exp:
            db.session.rollback()
            print(exp)


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
    print(112, session)
    if 'user_login' in session:
        del session['user_login']
    return redirect(url_for('index'))


@app.route('/')
def index():
    posts = BlogPost.query.order_by(BlogPost.date_posted.desc()).all()
    print(session)
    if 'user_login' not in session:
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


@app.route('/auth', defaults={'action': 'login'})
@app.route('/auth/<action>')
def auth(action):
    if not request.args.get('state'):
        session['last'] = request.referrer or url_for('index')
        if 'next' in request.args:
            session['next'] = url_for(request.args['next'])
        else:
            session['next'] = session['last']

    # User logged in, refresh
    if session.get('user') and action == 'refresh':
        if 'refresh_token' not in session['user']['token']:
            flash('Could not refresh, token not present', 'danger')
            return redirect(session['last'])
        google = OAuth2Session(
          app.config['GOOGLE_CLIENT_ID'],
          token=session['user']['token']
        )
        session['user']['token'] = google.refresh_token(
          'https://accounts.google.com/o/oauth2/token',
          client_id=app.config['GOOGLE_CLIENT_ID'],
          client_secret=app.config['GOOGLE_CLIENT_SECRET']
        )
        flash('Token refreshed', 'success')
        return redirect(session['next'])

    # User loggedin - logout &/or revoke
    if session.get('user'):
        if action == 'revoke':
            response = requests.get(
              'https://accounts.google.com/o/oauth2/revoke',
              params={'token': session['user']['token']['access_token']}
            )
            if response.status_code == 200:
                flash('Authorization revoked', 'warning')
            else:
                flash('Could not revoke token: {}'.format(response.content), 'danger')
        if action in ['logout', 'revoke']:
            del session['user']
            flash('Logged out', 'success')
        return redirect(session['last'])

    google = OAuth2Session(
      app.config['GOOGLE_CLIENT_ID'],
      scope=[
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
      ],
      redirect_uri=url_for('auth', _external=True),
      state=session.get('state')
    )

    # Initial client request, no `state` from OAuth redirect
    if not request.args.get('state'):
        url, state = google.authorization_url(
          'https://accounts.google.com/o/oauth2/auth',
          access_type='offline'
        )
        session['state'] = state
        return redirect(url)

    # Error returned from Google
    if request.args.get('error'):
        error = request.args['error']
        if error == 'access_denied':
            error = 'Not logged in'
        flash('Error: {}'.format(error), 'danger')
        return redirect(session['last'])

    # Redirect from google with OAuth2 state
    token = google.fetch_token(
      'https://accounts.google.com/o/oauth2/token',
      client_secret=app.config['GOOGLE_CLIENT_SECRET'],
      authorization_response=request.url
    )
    user = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
    user['token'] = token
    session['user'] = user
    flash('Logged in', 'success')
    print(227, session)
    if action == 'login':
        if not session.get('user_login'):
            login_oauth_user()
        session['user_login'] = True
    return redirect(url_for('index'))


if __name__ == '__main__':
    db.create_all()
    app.run(port=5000, debug=True)