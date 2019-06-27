from flask import abort, Blueprint

import datetime
import logging

from pebbles.models import InstanceToken
from pebbles.server import restful

authorize_instances = Blueprint('authorize_instances', __name__)


class AuthorizeInstancesView(restful.Resource):
    def get(self):

        return 200


class AuthorizeInstanceView(restful.Resource):
    def get(self, token_id, instance_id):

        instance_token = InstanceToken.query.filter_by(token=token_id).first()
        if not instance_token:
            logging.warn("instance token %s not found" % token_id)
            return abort(404)

        curr_time = datetime.datetime.utcnow()
        expires_on = instance_token.expires_on

        if curr_time > expires_on:
            logging.warn("instance token %s has expired" % token_id)
            return abort(410)

        if instance_token.instance_id != instance_id:
            logging.warn("instance id %s from the token does not match the instance_id %s passed as a parameter" % (instance_token.instance_id, instance_id))
            return abort(403)

        return {token_id: instance_id}, 200
