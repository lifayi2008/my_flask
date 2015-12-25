from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo, ValidationError
from ..models import User
from flask.ext.login import current_user

class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Login')

class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    username = StringField('Username', validators=[Required(), Length(1,64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, ')])
    password = PasswordField('Password', validators=[Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

class ChangePassForm(Form):
    old_password = PasswordField('Old password', validators=[Required()])
    password = PasswordField('New password', validators=[Required(), Length(6,32), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Change')
    
    def validate_old_password(self, field):
        if not current_user.verify_password(field.data):
            raise ValidationError('Old password wrong')
    
    def validate_password(self, field):
        if field.data == self.old_password.data:
            raise ValidationError('New password should not same as old password.')

class ResetPassRequestForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    submit= SubmitField('Send mail')

    def validate_email(self, field):
        if not User.query.filter_by(email=field.data).first():
            raise ValidationError('Email address not registration.')

class ResetPassForm(Form):
    password = PasswordField('New password', validators=[Required(), Length(6,32), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Reset')

class ChangeEmailForm(Form):
    password = PasswordField('Password', validators=[Required()])
    new_email = StringField('New Email', validators=[Required(), Length(1,64), Email()])
    submit = SubmitField('Submit')

    def validate_password(self, field):
        if not current_user.verify_password(field.data):
            raise ValidationError('Password wrong.')

    def validate_new_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidateionError('Email has been used.')
