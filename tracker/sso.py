from functools import wraps
from flask_login import login_required as flask_login_required
from flask import redirect, url_for
from tracker import oauth
from tracker import tracker
import json

from config import SSO_ENABLED

def login_required(func):
    if SSO_ENABLED:
        @wraps(func)
        def wrapped(*args, **kwargs):
            redirect_url = url_for('tracker.sso_auth', _external=True)
            return oauth.idp.authorize_redirect(redirect_url)
            #return func(*args, **kwargs)
        return wrapped 
    else:
        return flask_login_required(func)

@tracker.route('/sso-auth')
def sso_auth():
    token = oauth.idp.authorize_access_token()
    parsed_token = oauth.idp.parse_id_token(token)
    print(json.dumps(parsed_token, indent=2, sort_keys=True))
    return redirect('/')