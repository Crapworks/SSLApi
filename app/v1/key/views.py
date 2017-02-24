#!/usr/bin/env python
# -*- coding: UTF-8 -*-

from flask import jsonify
from flask import request
from flask import abort

from utils.x509 import ParameterError
from utils.x509 import X509Key

from app.base import ApiResource


class KeyResource(ApiResource):
    endpoint = 'key'
    url_prefix = '/key'
    url_rules = {
        'index': {
            'rule': ''
        }
    }

    def post(self):
        data = request.get_json()
        if not data:
            abort(400, 'no post data found')

        key = X509Key()
        try:
            key.generate(**data['key'])
        except ParameterError as err:
            abort(400, 'error generating key: {}'.format(err))

        return jsonify(key=key.pem)
