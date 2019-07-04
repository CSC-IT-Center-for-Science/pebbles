from flask import abort, request, Response, Blueprint

import datetime
import logging
import re

from pebbles.models import InstanceToken
from pebbles.server import restful

authorize_instances = Blueprint('authorize_instances', __name__)


class AuthorizeInstancesView(restful.Resource):
    def get(self):
        instance_token = ''
        instance_id = ''

        if 'X-ORIGINAL-URI' in request.headers:
            h_uri = request.headers['X-ORIGINAL-URI']
            regex_query_capture = re.search('.*\\?.*=(.*)&.*=(.*)', h_uri)
            if regex_query_capture and len(regex_query_capture.groups()) == 2:
                instance_token = regex_query_capture.group(1)
                instance_id = regex_query_capture.group(2)
        elif 'ORIGINAL-TOKEN' in request.headers and 'INSTANCE-ID' in request.headers:
            instance_token = request.headers['ORIGINAL-TOKEN']
            instance_id = request.headers['INSTANCE-ID']

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
        resp.headers["TOKEN"] = instance_token
        resp.headers["INSTANCE-ID"] = instance_id
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
