# from flask.ext.restful import fields, marshal_with, reqparse
from flask import abort, Blueprint

# import logging

from pebbles.models import db, Client
from pebbles.server import restful
from pebbles.views.commons import auth
from flask import g, jsonify
from werkzeug.security import gen_salt

clients = Blueprint('clients', __name__)


class Clients(restful.Resource):
    # parser = reqparse.RequestParser()
    # parser.add_argument('namespace', type=str)
    # parser.add_argument('key', type=str)

    @auth.login_required
    def get(self):
        user = g.user
        if not user:
            abort(422)
        item = Client(
            client_id=gen_salt(40),
            client_secret=gen_salt(50),
            _redirect_uris='http://localhost:8000/authorized',
            _default_scopes='email',
            user_id=user.id,
        )
        db.session.add(item)
        db.session.commit()
        return jsonify(
            client_id=item.client_id,
            client_secret=item.client_secret,
        )
