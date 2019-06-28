from flask import abort, request, Response, Blueprint

import datetime
import logging
from urlparse import urlparse, parse_qs

from pebbles.models import InstanceToken
from pebbles.server import restful

authorize_instances = Blueprint('authorize_instances', __name__)


class AuthorizeInstancesView(restful.Resource):
    def get(self):
        instance_token = ''
        instance_id = ''

        if 'X-ORIGINAL-URI' in request.headers:
            h_uri = request.headers['X-ORIGINAL-URI']
            parsed_uri = urlparse(h_uri)
            queryparams = parse_qs(parsed_uri)
            instance_token = queryparams['token'][0]
            instance_id = queryparams['instance_id'][0]
        if 'TOKEN' in request.headers and 'INSTANCE_ID' in request.headers:
            instance_token = request.headers['TOKEN']
            instance_id = request.headers['INSTANCE_ID']

        if not instance_token and not instance_id:
            logging.warn('No instance token or id found from the headers')
            return abort(401)

        instance_token = InstanceToken.query.filter_by(token=instance_token).first()
        if not instance_token:
            logging.warn("instance token %s not found" % instance_token)
            return abort(401)

        curr_time = datetime.datetime.utcnow()
        expires_on = instance_token.expires_on

        if curr_time > expires_on:
            logging.warn("instance token %s has expired" % instance_token)
            return abort(403)

        if instance_token.instance_id != instance_id:
            logging.warn("instance id %s from the token does not match the instance_id %s passed as a parameter" % (instance_token.instance_id, instance_id))
            return abort(403)

        resp = Response("Authorized")
        resp.headers["ORIGINAL_TOKEN"] = instance_token
        resp.headers["INSTANCE_ID"] = instance_id
        return resp, 200


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

        resp = Response("Authorized")
        resp.headers["ORIGINAL_TOKEN"] = token_id
        resp.headers["INSTANCE_ID"] = instance_id

        return resp, 200
