import sys
import os as os
import logging
from flask import Flask
from flask_migrate import upgrade as flask_upgrade_db_to_head
from flask_migrate import Migrate

from pebbles.models import db, bcrypt, Client, Grant, Token, User
from pebbles.config import BaseConfig, TestConfig

from flask_oauthlib.provider import OAuth2Provider
from datetime import datetime, timedelta

from pebbles.views.commons import auth
from flask import g, abort, request, render_template, jsonify


app = Flask(__name__, static_url_path='')
migrate = Migrate(app, db)

oauth = OAuth2Provider(app)


# Setup static files to be served by Flask for automated testing
@app.route('/')
def root():
    return app.send_static_file('index.html')


@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')


@app.route('/api/v1/oauth/token')
@oauth.token_handler
def access_token():
    return None


@app.route('/api/v1/oauth/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
@auth.login_required
def authorize(*args, **kwargs):
    logging.warn('Enter')
    user = g.user
    if not user:
        abort(404)
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        kwargs['user'] = user
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@app.route('/api/me')
@oauth.require_oauth()
def me(req):
    user = req.user
    return jsonify(username=user.username)


@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=User.query.filter_by(email='a@a.com').first(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    ).all()
    # make sure that every client has only one token connected to a user
    db.session.delete(toks)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(**token)
    tok.expires = expires
    tok.client_id = request.client.client_id
    tok.user_id = request.user.id
    db.session.add(tok)
    db.session.commit()
    return tok


test_run = set(['test', 'covtest']).intersection(set(sys.argv))

if test_run:
    app.dynamic_config = TestConfig()
else:
    app.dynamic_config = BaseConfig()

app.config.from_object(app.dynamic_config)

if app.config['ENABLE_SHIBBOLETH_LOGIN']:
    SSO_ATTRIBUTE_MAP = {
        "HTTP_AJP_SHIB_MAIL": (True, "email_id"),
        "HTTP_AJP_SHIB_EPPN": (True, "eppn"),
    }
    app.config.setdefault('SSO_ATTRIBUTE_MAP', SSO_ATTRIBUTE_MAP)
    app.config.setdefault('SSO_LOGIN_URL', '/login')
    app.config.setdefault('PREFERRED_URL_SCHEME', 'https')

bcrypt.init_app(app)
db.init_app(app)


def run_things_in_context(test_run):
    # This is only split into a function so we can easily test some of it's
    # behavior.
    with app.app_context():
        # upgrade to the head of the migration path (the default)
        # we might want to pass a particular revision id instead
        # in the future
        if os.environ.get("DB_AUTOMIGRATION", None) and \
           os.environ.get("DB_AUTOMIGRATION", None) not in ["0", 0] and \
           not test_run:
            flask_upgrade_db_to_head()


run_things_in_context(test_run)
