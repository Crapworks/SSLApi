#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import json

from os.path import dirname
from os.path import join

from flask import Flask
from flask import jsonify

from werkzeug.exceptions import default_exceptions
from werkzeug.exceptions import HTTPException

from app.v1.x509.views import X509Resource as X509ResourceV1
from app.v1.key.views import KeyResource as KeyResourceV1


class Config(dict):
    """A simple json config file loader

    :param str filename: path to the json file
    """
    def __init__(self, filename, datacenter=None):
        dict.__init__(self)
        config = json.load(open(filename))
        self.update(config)


def make_json_error(ex):
    """Error handler that creares json error messages"""
    if isinstance(ex, HTTPException):
        code = ex.code
        message = ex.description
    else:
        code = 500
        message = str(ex)

    response = jsonify(code=code, message=message)
    response.status_code = code

    if code == 401:
        response.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'

    return response


def create_app(config):
    app = Flask(__name__)
    app.template_folder = join(dirname(__file__), 'templates')
    app.static_folder = join(dirname(__file__), 'static')

    for code in default_exceptions.iterkeys():
        app.register_error_handler(code, make_json_error)

    app.config['USER_CONFIG'] = Config(config)
    app.register_blueprint(X509ResourceV1.as_blueprint(), url_prefix='/v1/x509')
    app.register_blueprint(KeyResourceV1.as_blueprint(), url_prefix='/v1/key')

    return app
