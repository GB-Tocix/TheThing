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


class Question():
    def __init__(self, ques, optA, optB, optC, optD, optX):
        self.ques = ques
        self.optA = optA
        self.optB = optB
        self.optC = optC
        self.optD = optD
        self.optX = optX


pb = [Question(ques='客户的交易结算资金、证券资产管理客户的委托资产属于客户，与证券公司、指定商业银行、资产托管机构的自有资产( )', optA='A.混合管理', optB='B.相互独立、分别管理', optC='C.适当独立', optD='D.共同管理', optX='2')
,Question(ques='客户的交易结算资金、证券资产管理客户的委托资产属于客户，与证券公司、指定商业银行、资产托管机构的自有资产( )', optA='A.混合管理', optB='B.相互独立、分别管理', optC='C.适当独立', optD='D.共同管理', optX='2')
,Question(ques='某投资者预期未来一段时间铜价将会下跌，则投资者最不可能采用的措施是( )', optA='A.卖出仓库中储存的现货铜', optB='B.将其持有的某期货交易所的期货铜多头头寸平仓', optC='C.买入某铜矿公司的股票且此公司披露已将铜价波动风险对冲', optD='D.买入某金融机构发行的挂钩铜期货且看空铜价的结构化产品', optX='3')
,Question(ques='因持有股票而享有的配股权，从配股除权日起到配股确认日止，如果股票收盘价低于配股价，则配股权的估值价格是( )', optA='A.收盘价高于配股价的差额', optB='B.配股价', optC='C.零', optD='D.收盘价', optX='3')
,Question(ques='投资政策说明书的制定，主要依据投资者的( )Ⅰ.投资需求Ⅱ.财务状况Ⅲ.投资限制Ⅳ.投资偏好', optA='A.Ⅰ、Ⅱ、Ⅲ', optB='B.Ⅰ、Ⅲ、Ⅳ', optC='C.Ⅰ、Ⅱ、Ⅳ', optD='D.Ⅰ、Ⅱ、Ⅲ、Ⅳ', optX='4')
,Question(ques='关于利率互换和货币互换的描述，正确的是( )', optA='A.货币互换的合约双方互换的是不同币种为单位的利率', optB='B.利率互换的合约双方交换的是双方认为具有相等经济价值的现金流', optC='C.利率互换的合约双方互换的是不同币种下的相同利率', optD='D.货币互换的合约的一方具有货币交换的权利，而没有货币交换的义务', optX='2')
,Question(ques='关于债券当期收益率与到期收益率，下列表达正确的是( )', optA='A.当期收益率的变动总是预示着到期收益率的反向变动', optB='B.票面利率不变的情况下，当期收益率的变动总是预示着到期收益率的反向变动', optC='C.票面利率不变的情况下，当期收益率的变动与到期收益率的变动不存在相关性', optD='D.当期收益率的变动总是预示着到期收益率的同向变动', optX='4')
,Question(ques='关于股票型指数基金，以下表述错误的是( )', optA='A.跟踪指数可以是综合指数，也可以是行业分类指数', optB='B.可以采用完全复制方法，也可以采用抽样复制方法来构造股票组合', optC='C.股票型指数基金的投资对象可能包括货币市场工具和现金资产', optD='D.股票型指数基金的业绩取决于基金经理的选股能力', optX='4')
,Question(ques='对于采用自下而上策略的股票型基金，以下说法错误的是( )', optA='A.个股的选择与权重受到基金契约、基金合规等方面的限制', optB='B.股票投资比例主要取决于基金经理对宏观经济形势的预测', optC='C.基金经理可不考虑行业与风格的配置，只是选择个股', optD='D.基金资产中股票的配置比例不低于80%', optX='2')
,Question(ques='货币市场工具不包括( )', optA='A.397天以内的资产支持专项计划', optB='B.1年以内的债券回购', optC='C.1年以内的定期存款', optD='D.397天以内的债券', optX='2')
,Question(ques='( )是基金估值的第一责任主体', optA='A.托管机构', optB='B.中国证券投资基金业协会', optC='C.基金管理公司', optD='D.中国证券业协会', optX='3')
,Question(ques='上海黄金交易所系统在撮合成交时，当前一成交价≥买入价≥卖出价时，则撮合成交价为( )', optA='A.买入价', optB='B.前一成交价', optC='C.卖出价', optD='D.都不对', optX='1')
,Question(ques='下列有关现货延期Au(T+D)合约与黄金期货合约的不同点，说法正确的是( )', optA='A.Au(T+D)每个交易日都可以进行交收申报，而黄金期货则在指定日期进行交割，其他时间不能交割。', optB='B.Au(T+D)不是保证金交易品种，不能进行双向交易，而黄金期货则是保证金交易品种，可以进行双向交易。', optC='C.Au(T+D)利用延期补偿费机制来平抑供求矛盾，而黄金期货则利用中立仓机制满足交收需求。', optD='D.投资者可以利用Au(T+D)进行套期保值交易，而黄金期货则不具备套期保值功能。', optX='1')
,Question(ques='现货实盘交易中，当天卖出黄金的资金，（ ）可用于当天的交易。', optA='A.70%', optB='B.80%', optC='C.90%', optD='D.100%', optX='4')
,Question(ques='上海金人民币定价交易是指市场参与者在交易所平台上，按照（ ）的集中交易方式，在达到市场量价相对平衡后，最终形成上海金人民币基准价的交易)', optA='A.以价询量、数量撮合', optB='B.时间优先、价格优先', optC='C.最大成交量、最小剩余量', optD='D.以价询量、价格优先', optX='1')
,Question(ques='询价业务常见的交易类型不包括( )', optA='A.即期', optB='B.远期', optC='C.掉期', optD='D.期货', optX='4')
,Question(ques='某套利者买入5月份大豆期货合约的同时卖出9月份大豆期货合约，价格分别为3850元/吨和3900元/吨，平仓时两个合约的期货价格分别变为3910元/吨和3930元/吨，则该套利者平仓时的价差为()元/吨。', optA='A.-20', optB='B.-50', optC='C.20', optD='D.50', optX='3')
,Question(ques='我国客户下单的方式中，最主要的方式是( )', optA='A.书面下单', optB='B.电话下单', optC='C.互联网下单', optD='D.口头下单', optX='3')
,Question(ques='需求量的变动一般是指在影响需求的其他因素不变的前提下，由于()变化所引起的对该产品需求的变化。( )', optA='A.收入水平', optB='B.相关商品价格', optC='C.产品本身价格', optD='D.预期与偏好', optX='3')
,Question(ques='某出口商担心日元贬值而采取套期保值，可以( )', optA='A.买入日元期货买权', optB='B.卖出欧洲日元期货', optC='C.卖出日元期货', optD='D.卖出日元期货卖权', optX='3')
,Question(ques='某行权价为210元的看跌期权，对应的标的资产当前价格为207元，当前该期权的权利金为8元时，该期权的时间价值为()元。', optA='A.3', optB='B.5', optC='C.8', optD='D.11', optX='2')]


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')


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


@app.route('/bankA/<tar>', methods=['GET', 'POST'])
@login_required
def bankA(tar):
    class QuestionForm(Form):
        tmpQ = pb[10 + int(tar)]
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

    return render_template('bankA.html', cur=int(tar), condition=condition, form=form, question=question, current_time=datetime.utcnow())


@app.route('/bankB/<tar>', methods=['GET', 'POST'])
@login_required
def bankB(tar):
    class QuestionForm(Form):
        tmpQ = pb[5 + int(tar)]
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

    return render_template('bankB.html', cur=int(tar), condition=condition, form=form, question=question, current_time=datetime.utcnow())


@app.route('/bankC/<tar>', methods=['GET', 'POST'])
@login_required
def bankC(tar):
    class QuestionForm(Form):
        tmpQ = pb[int(tar)]
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

    return render_template('bankC.html', cur=int(tar), condition=condition, form=form, question=question, current_time=datetime.utcnow())


@app.route('/bankD/<tar>', methods=['GET', 'POST'])
@login_required
def bankD(tar):
    class QuestionForm(Form):
        tmpQ = pb[15 + int(tar)]
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

    return render_template('bankD.html', cur=int(tar), condition=condition, form=form, question=question, current_time=datetime.utcnow())


@app.route('/knowledge/2')
def reality():
    return render_template('reality.html', current_time=datetime.utcnow())