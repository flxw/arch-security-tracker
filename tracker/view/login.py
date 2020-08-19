from flask import redirect
from flask import render_template
from flask import url_for
from flask_login import current_user
from flask_login import login_user
from flask_login import logout_user
from werkzeug.exceptions import Unauthorized

from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from config import SSO_ENABLED
from tracker import tracker, oauth
from tracker.form import LoginForm
from tracker.model.user import User
from tracker.user import user_assign_new_token
from tracker.user import user_invalidate


@tracker.route('/login', methods=['GET', 'POST'])
def login():
    # TODO start OIDC flow here if SSO is enabled
    if SSO_ENABLED:
        if False:
            return redirect(url_for('tracker.index'))
        else:
            return redirect(url_for('tracker.list_user'))
    else:
        if current_user.is_authenticated:
            return redirect(url_for('tracker.index'))

        form = LoginForm()
        if not form.validate_on_submit():
            status_code = Unauthorized.code if form.is_submitted() else 200
            return render_template('login.html',
                                title='Login',
                                form=form,
                                User=User,
                                password_length={'min': TRACKER_PASSWORD_LENGTH_MIN,
                                                 'max': TRACKER_PASSWORD_LENGTH_MAX}), status_code

        user = user_assign_new_token(form.user)
        user.is_authenticated = True
        login_user(user)
        return redirect(url_for('tracker.index'))


@tracker.route('/logout', methods=['GET', 'POST'])
def logout():
    # TODO clear SSO session
    if not current_user.is_authenticated:
        return redirect(url_for('tracker.index'))

    user_invalidate(current_user)
    logout_user()
    return redirect(url_for('tracker.index'))


@tracker.route('/sso-auth')
def sso_auth():
    from tracker import db

    # login the user here, create a session and set role
    token = oauth.idp.authorize_access_token()
    parsed_token = oauth.idp.parse_id_token(token)
    # check if user can be matched against local db of users
    user = db.get(User, email=parsed_token.get('email'))

    if user:
        user = user_assign_new_token(user)
        user.is_authenticated = True
        login_user(user)
    elif len(parsed_token.get('roles')) == 0:
        return redirect(url_for('tracker.index'))
    else:
        # user does not exist in local db
        # need to create him to leverage existing user access controls
        from tracker.user import random_string, hash_password

        user = User()
        user.name = parsed_token.get('preferred_username')
        user.email = parsed_token.get('email')
        user.salt = random_string()
        user.password = hash_password('wasd', user.salt)
        user.role = parsed_token.get('roles')[0] 
        user.active = True

        db.session.add(user)
        db.session.commit()

    return redirect(url_for('tracker.index'))
