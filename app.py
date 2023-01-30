from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(100), unique=True)

    def __init__(self, username, password, email=None):
        self.username = username
        self.password = password
        self.email = email

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username has unfortunately been taken :( Please choose a different username.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class ChangePass(FlaskForm):
    newpass = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "New Password"})

    submit = SubmitField('Change Password')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in!')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong Username/Password")
                return render_template('login.html', form=form)
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == "POST":
        #if request.form["email"] != "":
        email = request.form["email"]
        #if request.form["delete"] != "":
            #delete = request.form["delete"]
        #email validator
        if email != "":
            try:
                validate_email(email)
                current_user.email = email
                flash("Email Successfully Updated!")
                db.session.commit()
            except EmailNotValidError:
                flash("Please enter a valid email")
        elif email == "":
            flash("Please enter something")
        #if delete != "":
            #print("a")

    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have successfully logged out!')
    return redirect(url_for('login'))

@app.route('/error')
def error():
    return render_template('error.html')

@app.route('/users')
def users():
    return render_template('users.html', values=User.query.all())

@app.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    if current_user.email is not None:
        if request.method == "POST":
            delete = request.form["delete"]
            if delete == "DELETE":
                current_user.email = None
                flash("Email Successfully Deleted :(")
                db.session.commit()
                return render_template('dashboard.html')
            else:
                flash("Error, check if DELETE is in full caps and spelt correctly.")
    else:
        flash("There is no email to delete")
        return render_template('dashboard.html')
    return render_template('delete.html')

@app.route('/change', methods=['GET', 'POST'])
@login_required
def change():
    form = ChangePass()

    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.newpass.data):
            flash("Please enter a different password")
            return render_template('change.html', form=form)
        else:
            hashed_newpassword = bcrypt.generate_password_hash(form.newpass.data)
            current_user.password = hashed_newpassword
            flash("Password Successfully Updated! Please Re-Login")
            db.session.commit()
            logout_user()
            return redirect(url_for('login'))
    return render_template('change.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)
