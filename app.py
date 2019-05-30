#!usr/bin/python

import os
from flask import Flask, render_template, redirect, session, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user, AnonymousUserMixin
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, Form
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, BooleanField, PasswordField, ValidationError, TextAreaField, RadioField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'hard to guess string'
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


bootstrap = Bootstrap(app)
moment = Moment(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)

login_manager.session_protection = 'strong'
login_manager.login_view = 'login'  # 不满足login_required的跳转
login_manager.login_message = "请先登录，后使用题库！"


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Done(db.Model):
    __tablename__='dones'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                        primary_key=True)
    ques_id = db.Column(db.Integer, db.ForeignKey('questions.id'),
                        primary_key=True)


class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    ques = db.Column(db.Text)
    optA = db.Column(db.Text)
    optB = db.Column(db.Text)
    optC = db.Column(db.Text)
    optD = db.Column(db.Text)
    optX = db.Column(db.String)
    bedone = db.relationship('Done',
                            foreign_keys=[Done.ques_id],
                            backref=db.backref('ques', lazy='joined'),
                            lazy='dynamic',
                            cascade='all, delete-orphan')

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    done = db.relationship('Done',
                           foreign_keys=[Done.user_id],
                           backref=db.backref('user', lazy='joined'),
                           lazy='dynamic',
                           cascade='all, delete-orphan')

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username

    def func_done(self, ques):
        if not self.is_done(ques):
            d = Done(user=self, ques=ques)
            db.session.add(d)

    def func_undone(self, ques):
        d = self.done.filter_by(ques_id=ques.id).first()
        if d:
            db.session.delete(d)

    def is_done(self, ques):
        return self.done.filter_by(ques_id=ques.id).first() is not None


class PostForm(FlaskForm):
    body = TextAreaField("记录下你今天的学习心情吧，一起分享吧！", validators=[DataRequired()])
    submit = SubmitField('提交')


class LoginForm(Form):
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('密码', validators=[DataRequired()])
    remember_me = BooleanField('记住我的登陆状态')
    submit = SubmitField('登陆')


class RegistrationForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    username = StringField('用户名', validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
               'Usernames must have only letters, numbers, dots or '
               'underscores')])
    password = PasswordField('密码', validators=[
        DataRequired(), EqualTo('password2', message='两次密码必须一致')])
    password2 = PasswordField('请确认密码', validators=[DataRequired()])
    submit = SubmitField('注册')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('该邮箱已经被注册过了')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('这个用户名已经被使用了')


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser


def db_init():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/secret')
@login_required
def secret():
    return 'Only authenticated users are allowed!'


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('.index'))
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('index.html', posts=posts, form=form, current_time=datetime.utcnow())


@app.route('/community', methods=['GET', 'POST'])
def community():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('.community'))
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('community.html', posts=posts, form=form, current_time=datetime.utcnow())


@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form, current_time=datetime.utcnow())


@app.route('/auth/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now login.')
        return redirect(url_for('login'))
    return render_template('auth/register.html', form=form, current_time=datetime.utcnow())


@app.route('/about')
def about():
    return render_template('about.html', current_time=datetime.utcnow())


@app.route('/knowledge')
def knowledge():
    return render_template('knowledge.html', current_time=datetime.utcnow())


@app.route('/bankA', methods=['GET', 'POST'])
@login_required
def bankA(tar):
    class QuestionForm(Form):
        tmpQ = pb[5 + tar]
        option = RadioField('Label', choices=[
            ('1', tmpQ.optA),
            ('2', tmpQ.optB),
            ('3', tmpQ.optC),
            ('4', tmpQ.optD)],
                            default=0, validators=[DataRequired()])
        submit = SubmitField('确认')

        def the_answer(self):
            return self.tmpQ.optX

        def the_question(self):
            return self.tmpQ.ques

        def the_obj(self):
            return self.tmpQ

    form = QuestionForm()
    question = form.the_question()
    ans = form.the_answer()

    condition = 0

    if form.validate_on_submit():
        if form.option.data is ans:
            condition = 1
        else:
            condition = 2

    return render_template('bankA.html', condition=condition, form=form, question=question, current_time=datetime.utcnow())


@app.route('/bankB', methods=['GET', 'POST'])
@login_required
def bankB(tar=1):
    class QuestionForm(Form):
        tmpQ = pb[5 + tar]
        option = RadioField('Label', choices=[
            ('1', tmpQ.optA),
            ('2', tmpQ.optB),
            ('3', tmpQ.optC),
            ('4', tmpQ.optD)],
                            default=0, validators=[DataRequired()])
        submit = SubmitField('确认')

        def the_answer(self):
            return self.tmpQ.optX

        def the_question(self):
            return self.tmpQ.ques

        def the_obj(self):
            return self.tmpQ

    form = QuestionForm()
    question = form.the_question()
    ans = form.the_answer()

    condition = 0

    if form.validate_on_submit():
        if form.option.data is ans:
            condition = 1
        else:
            condition = 2

    return render_template('bankB.html', condition=condition, form=form, question=question, current_time=datetime.utcnow())


@app.route('/bankC', methods=['GET', 'POST'])
@login_required
def bankC(tar=1):
    class QuestionForm(Form):
        tmpQ = pb[10 + tar]
        option = RadioField('Label', choices=[
            ('1', tmpQ.optA),
            ('2', tmpQ.optB),
            ('3', tmpQ.optC),
            ('4', tmpQ.optD)],
                            default=0, validators=[DataRequired()])
        submit = SubmitField('确认')

        def the_answer(self):
            return self.tmpQ.optX

        def the_question(self):
            return self.tmpQ.ques

        def the_obj(self):
            return self.tmpQ

    form = QuestionForm()
    question = form.the_question()
    ans = form.the_answer()

    condition = 0

    if form.validate_on_submit():
        if form.option.data is ans:
            condition = 1
        else:
            condition = 2

    return render_template('bankC.html', condition=condition, form=form, question=question, current_time=datetime.utcnow())


@app.route('/bankD', methods=['GET', 'POST'])
@login_required
def bankD(tar=1):
    class QuestionForm(Form):
        tmpQ = pb[15 + tar]
        option = RadioField('Label', choices=[
            ('1', tmpQ.optA),
            ('2', tmpQ.optB),
            ('3', tmpQ.optC),
            ('4', tmpQ.optD)],
                            default=0, validators=[DataRequired()])
        submit = SubmitField('确认')

        def the_answer(self):
            return self.tmpQ.optX

        def the_question(self):
            return self.tmpQ.ques

        def the_obj(self):
            return self.tmpQ

    form = QuestionForm()
    question = form.the_question()
    ans = form.the_answer()

    condition = 0

    if form.validate_on_submit():
        if form.option.data is ans:
            condition = 1
        else:
            condition = 2

    return render_template('bankD.html', condition=condition, form=form, question=question, current_time=datetime.utcnow())


@app.route('/knowledge/2')
def reality():
    return render_template('reality.html', current_time=datetime.utcnow())