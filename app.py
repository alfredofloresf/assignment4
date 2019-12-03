from flask import Flask, render_template, redirect, url_for, make_response, flash, request, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
import subprocess, random
import os
from datetime import datetime
from wtforms import StringField, PasswordField, BooleanField, validators, SubmitField, TextAreaField, IntegerField
from wtforms.validators import InputRequired, Email, Length, ValidationError, DataRequired, Regexp
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from subprocess import check_output
from sqlalchemy.orm import relationship, sessionmaker

app = Flask(__name__)
#app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SECRET_KEY'] = open("/run/secrets/csrf_secret_key_password", "r").read().strip()
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/appsec/PycharmProjects/Assignment3/database.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



def validate_phone(form, field):

    if len(field.data) > 14:
        raise ValidationError('Failure: This is an invalid phone number Phone numbers must contain 10 digits')
    else:
        sanitized_phone_number = field.data.strip(' ()-')
        if len(sanitized_phone_number) == 10 or len(sanitized_phone_number) == 11:
            for i in range(len(sanitized_phone_number)):
                if sanitized_phone_number[i].isnumeric():
                    continue
                else:
                    raise ValidationError('Failure: Phone numbers must only contain numbers')
        else:
            raise ValidationError('Failure: Phone numbers must contain 10 digits (or 11 with country code)')




class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    twofa = db.Column(db.String(50))
    password = db.Column(db.String(80))
    role = db.Column(db.String(6), nullable=True)

class Login(db.Model):
    __tablename__ = 'login'
    id = db.Column(db.Integer, nullable=False, autoincrement=True, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    login_time = db.Column(db.DateTime, index=True)
    logout_time = db.Column(db.DateTime, index=True)

class Submission(db.Model):
      __tablename__ = 'submission'
      id = db.Column('id', db.Integer, primary_key = True)
      user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
      text = db.Column(db.String(500))
      result = db.Column(db.String(500))

class QueryHistory(db.Model):
    __tablename__ = 'queries'
    queryid = db.Column(db.Integer, nullable=False, autoincrement = True, primary_key=True)
    querytext = db.Column(db.String(4000), nullable=False)
    queryresult = db.Column(db.String(4000), nullable=False)
    username = db.Column(db.String(20), nullable=False)





# class Spelling_History(db.Model):
#     __tablename__ = "spelling_history"
#     id = db.Column(db.Integer, primary_key=True)
#     query_text = db.Column(db.String(), nullable=False)
#     query_result = db.Column(db.String(), nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('users.id'))


##################################################################################################################
class SpellCheckForm(FlaskForm):
    inputtext = TextAreaField('Text', validators=[InputRequired()], id="inputtext", render_kw={"rows": 4, "cols": 100})
    textout = TextAreaField('Text out', id="textout", render_kw={"disabled": "disabled", "rows": 4, "cols": 100})
    misspelled = TextAreaField('Misspelled', id="misspelled", render_kw={"disabled": "disabled", "rows": 4, "cols": 100})
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    username = StringField('Username', id='uname', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', id='pword', validators=[InputRequired(), Length(min=4, max=20)])
    twofa = StringField('two_fa', id='2fa', validators=[validate_phone, validators.Optional()])
    remember = BooleanField('remember me')


class HistoryForm(FlaskForm):
    uname = StringField('Username', validators=[InputRequired(), Regexp(r'^[\w.@+-]+$'), Length(min=4, max=25)], id='userquery')
    submit = SubmitField('Submit')

class LoginHistoryForm(FlaskForm):
    uid = StringField('UserID', validators=[DataRequired()], id="userid")
    submit = SubmitField('Search')

class HistoryQueryForm(FlaskForm):
    query_text = TextAreaField('Query Text', id='querytext', render_kw={'readonly': True})
    query_results = TextAreaField('Query Results', id='queryresults', render_kw={'readonly': True})


class RegisterForm(FlaskForm):
    username = StringField('Username', id='uname', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', id='pword', validators=[InputRequired(), Length(min=4, max=20)])
    # twofa = StringField('2fa', id='2fa', validators=[InputRequired(), Length(max=50)])
    twofa = StringField('two_fa', id='2fa', validators=[validate_phone, validators.Optional()])

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Failure: Username is already in use')

####################################################################################################################

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    result = None

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
               # time_login = datetime.now()
                result = "success"
                # login_user(user, remember=form.remember.data)
                new_login = Login(user_id=user.id, login_time=datetime.now(), logout_time=None)
                db.session.add(new_login)
                db.session.commit()
                return render_template('login.html', form=form, result=result)
        return redirect(url_for('index'))
    return render_template('login.html', form=form, result=result)


def check_words(filename):
    stdout = check_output(['./a.out',filename, 'wordlist.txt']).decode('utf-8').replace('\n',', ')[:-2]
    return stdout


@app.route("/history", defaults={"query": None}, methods=['POST', 'GET'])
@app.route("/history/<query>")
def history(query):
    if 'user_id' in session:
        form = HistoryForm()
        user = User.query.filter_by(id=session['user_id']).first()
        if query != None:
            submission_id = int(query.replace("query", ""))
            # if user is admin, allow access to any submission by not filtering on user id
            if user.role:
                submission = Submission.query.filter_by(id=submission_id).first()
                user = User.query.filter_by(id=submission.user_id).first()
            else:
                submission = Submission.query.filter_by(user_id=session['user_id'], id=submission_id).first()
            if submission is None:
                flash("Sorry, that submission doesn't exist", "failure")
            return render_template("submission.html", submission=submission, user=user)
        else:
            if user.role and form.validate_on_submit():
                submissions = Submission.query.join(User).filter_by(username=form.uname.data).all()
                count = Submission.query.join(User).filter_by(username=form.uname.data).count()
            else:
                submissions = Submission.query.filter_by(user_id=session['user_id']).all()
                count = Submission.query.filter_by(user_id=session['user_id']).count()

            return render_template("history.html", submissions=submissions, count=count, user=user, form=form)
    else:
        return redirect(url_for('login'))


@app.route('/login_history', methods=['GET', 'POST'])
def login_history():
    form = LoginHistoryForm()
    if current_user.username is not None:
        admin = False
        curr_user = User.query.filter(User.username == current_user.username).first()
        if curr_user.role == "admin":
            admin = True
        if admin and form.validate_on_submit():
            user = User.query.filter(User.id == form.uid.data).first()
            logins = Login.query.filter(Login.user_id == user.id).all()
            assert(logins is not None)
            assert(len(logins) !=0)
            return render_template("login_history.html", form=None, logins=logins)
        elif admin:
            return render_template("login_history.html", form=form, logins=None)
    return render_template(url_for('spell_check'))



@app.route('/spell_check',methods = ['GET', 'POST'])
def spell_check():
    if 'user_id' in session:
        form = SpellCheckForm()
        if form.validate_on_submit():
            text = form.inputtext.data
            # set textout field to be input text
            form.textout.data = form.inputtext.data
            form.inputtext.data = ""

            # define filename to include user_id and a random number
            user_id = session['user_id']
            filename = str(user_id) + '-' + str(random.randint(1, 1000)) + '.txt'

            # create file and set output of check_words to misspelled input text
            with open(filename, 'w') as f:
                f.write(str(text))
            if os.path.isfile(filename):
                form.misspelled.data = check_words(filename)
                os.remove(filename)
                submission = Submission(user_id = user_id, text=text, result=form.misspelled.data)

                db.session.add(submission)
                db.session.commit()
            else:
                print("Error: %s file not found" % filename)

        return render_template("spell_check.html", form=form)
    else:
        return redirect(url_for('login'))




@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, twofa=form.twofa.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1 id="success">success</h1>'
        #flash('Your account has been created! You are not able to log in', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)



@app.route('/logout')
@login_required
def logout():
    login = Login.query.filter_by(user_id=current_user.id).order_by(Login.id.desc()).first()
    login.logout_time = datetime.now()
    logout_user()
    db.session.commit()

    return redirect(url_for('index'))

if __name__ == '__main__':
   # app.run(debug=True)
   app.run(debug=True, host='0.0.0.0')