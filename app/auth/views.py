from flask import render_template, redirect, request, url_for, flash, current_app
from flask.ext.login import login_user, login_required, logout_user, current_user
from . import auth
from ..models import User
from .forms import LoginForm, RegistrationForm, ChangePassForm, ResetPassRequestForm, ResetPassForm, ChangeEmailForm
from .. import db
from ..email import send_email
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account', 'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been send to you by email.')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))

@auth.before_app_request
def before_request():
    if current_user.is_authenticated and not current_user.confirmed and request.endpoint[:5] != 'auth.' and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Accouent', 'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has sent to you by email.')
    return redirect(url_for('main.index'))

@auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePassForm()
    if form.validate_on_submit():
        current_user.password = form.password.data
        db.session.add(current_user)
        logout_user()
        flash('Password has changed, please relogin.')
        return redirect(url_for('.login'))
    return render_template('auth/change_password.html', form=form)

@auth.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    form = ResetPassRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        token = user.generate_reset_token()
        send_email(user.email, 'Reset Your Password', 'auth/email/reset_password', token=token)
        flash('A email has been send to you.')
        return redirect(url_for('main.index'))
    return render_template('auth/reset_password_request.html', form=form)

@auth.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    form = ResetPassForm()
    if form.validate_on_submit():
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            flash('The confirmation link is invalid or has expired.')
            return redirect(url_for('main.index'))
        user = User.query.filter_by(email=data.get('email')).first()
        if user and user.id == data.get('reset'):
            user.password = form.password.data
            db.session.add(user)
            flash('Your password has been reset, please login')
            return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)

@auth.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        token =  current_user.generate_changeemail_token(form.new_email.data)
        send_email(form.new_email.data, 'Change Email', 'auth/email/change_email', token=token, user=current_user)
        flash('A email has been send to you.')
        return redirect(url_for('main.index'))
    return render_template('auth/change_email.html', form=form)

@auth.route('/changeemail/<token>')
@login_required
def changeemail(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except:
        flash('The confirmation link is invalid or has expired.')
        return redirect(url_for('main.index'))
    if current_user.id != data.get('changeemail'):
        flash('The confirmation link is invalid or has expired.')
        return redirect(url_for('main.index'))
    current_user.email = data.get('newemail')
    db.session.add(current_user)
    flash('Your email has changed.')
    return redirect(url_for('main.index'))
