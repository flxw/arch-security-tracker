from unittest.mock import patch

import pytest

from config import SSO_GUEST_GROUP
from config import SSO_REPORTER_GROUP
from config import SSO_SECURITY_TEAM_GROUP
from tracker.model import User
from tracker.model.enum import UserRole
from tracker.view.login import condense_user_groups_to_role
from tracker.view.login import sso_auth
from flask_login import current_user

from .conftest import create_user

DEFAULTEMAIL = "cyberwehr12345678@cyber.cyber"
UPDATEDEMAIL = "cyberwehr1@cyber.cyber"
TESTINGSUB = "wasd"
TESTINGNAME = "Peter"

class MockedIdp(object):
    def __init__(self, email, sub=None, groups=["Administrator"], verified=True):
        self.email = email
        self.sub = sub
        self.groups = groups
        self.verified = verified

    def authorize_access_token(self):
        return "Schinken"

    def parse_id_token(self, token):
        return {
            "sub": self.sub,
            "email_verified": self.verified,
            "email": self.email,
            "groups": self.groups,
            "preferred_username": TESTINGNAME
        }

@patch("tracker.oauth.idp", MockedIdp(UPDATEDEMAIL, TESTINGSUB), create=True)
@create_user(email=DEFAULTEMAIL, idp_id = TESTINGSUB)
def test_successful_authentication_and_role_email_update(app, db):
    initial_user = User.query.all()[0]
    assert initial_user.email != UPDATEDEMAIL
    assert initial_user.role != UserRole.administrator

    with app.test_request_context('/sso-auth'):
        sso_auth()
        assert len(User.query.all()) == 1
        assert current_user.is_authenticated
        assert current_user.email == UPDATEDEMAIL
        assert current_user.role == UserRole.administrator

@patch('tracker.oauth.idp', MockedIdp(DEFAULTEMAIL, "STONKS"), create=True)
@create_user(idp_id = "wasd")
def test_impersonation_prevention(app, db):
    user_state_before = User.query.all()[0]
    assert user_state_before.email == DEFAULTEMAIL
    assert user_state_before.role != UserRole.guest

    with app.test_request_context('/sso-auth'):
        sso_auth()

    all_users = User.query.all()
    assert len(all_users) == 1

    user_state_after = all_users[0]
    assert not user_state_after.is_authenticated
    assert user_state_after.email == DEFAULTEMAIL
    assert user_state_after.role != UserRole.guest

@patch('tracker.oauth.idp', MockedIdp(DEFAULTEMAIL, TESTINGSUB, groups=[]), create=True)
def test_group_constraint(app, db):
    with app.test_request_context('/sso-auth'):
        sso_auth()

    assert not User.query.all()

@patch('tracker.oauth.idp', MockedIdp(DEFAULTEMAIL, TESTINGSUB), create=True)
def test_jit_provisioning(app, db):
    with app.test_request_context('/sso-auth'):
        sso_auth()

        assert current_user.is_authenticated
        assert current_user.email == DEFAULTEMAIL
        assert current_user.role == UserRole.administrator
        assert current_user.idp_id == TESTINGSUB
        assert current_user.name == TESTINGNAME
        assert current_user.active

@patch('tracker.oauth.idp', MockedIdp(DEFAULTEMAIL, TESTINGSUB, verified=False), create=True)
def test_verified_email_requirement(app):
    with app.test_request_context('/sso-auth'):
        sso_auth()

    assert not User.query.all()


def test_correct_group_role_filtering():
    assert condense_user_groups_to_role([]).is_guest
    assert condense_user_groups_to_role(['random']).is_guest
    assert condense_user_groups_to_role([SSO_GUEST_GROUP, SSO_SECURITY_TEAM_GROUP]).is_security_team
    assert condense_user_groups_to_role([SSO_REPORTER_GROUP, SSO_REPORTER_GROUP]).is_reporter
