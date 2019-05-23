from flask import abort, Blueprint

# import logging

from pebbles.models import db, Client, Grant
from pebbles.server import restful
from pebbles.views.commons import auth
from pebbles.utils import requires_admin
from flask import g, jsonify
from werkzeug.security import gen_salt
from flask.ext.restful import reqparse


oauth_clients = Blueprint('oauth_clients', __name__)


class OAUTHClients(restful.Resource):
    @auth.login_required
    @requires_admin
    def post(self):
        user = g.user
        if not user:
            abort(422)
        item = Client(
            client_id=gen_salt(40),
            client_secret=gen_salt(50),
            _redirect_uris='http://localhost:8000/authorized',
            _default_scopes='email_id',
            user_id=user.id,
        )
        db.session.add(item)
        db.session.commit()
        return jsonify(
            client_id=item.client_id,
            client_secret=item.client_secret,
        )


class OAUTHGrant(restful.Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('client_id', type=str)

    @auth.login_required
    @requires_admin
    def get(self, group_id):
        args = self.parser.parse_args()
        client_id = args.client_id
        grant = Grant.query.filter_by(client_id=client_id).first()
        if not grant:
            abort(404)
        return jsonify(
            authorization_code=grant.code
        )
