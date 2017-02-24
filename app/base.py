import json

from flask import Blueprint
from flask.views import MethodView

from utils.x509 import X509Key
from utils.x509 import X509Cert
from utils.x509 import X509CertReq


class BootstrapCA(object):
    def __init__(self, config):
        with open(config) as fh:
            self.config = json.load(fh)

    def generate(self):
        key = X509Key()
        key.generate(**self.config['key'])

        req = X509CertReq()
        req.generate(key=key.key, name=self.config['names'])

        cert = X509Cert()
        cert.generate(issuerKey=key.key, issuerCert=False, req=req.request)

        return {'key': key.pem, 'certificate': cert.pem}


class ApiResource(MethodView):
    """Bluebrint wrapper for MethodViews"""

    endpoint = None
    url_prefix = None
    url_rules = {}

    @classmethod
    def as_blueprint(cls, name=None):
        name = name or cls.endpoint
        blueprint = Blueprint(name, cls.__module__, url_prefix=cls.url_prefix)
        for endpoint, options in cls.url_rules.iteritems():
            url_rule = options.get('rule', '')
            defaults = options.get('defaults', {})
            blueprint.add_url_rule(url_rule, defaults=defaults, view_func=cls.as_view(endpoint))
        return blueprint
