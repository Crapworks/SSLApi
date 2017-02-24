#!/usr/bin/env python
# -*- coding: UTF-8 -*-

from flask import jsonify
from flask import request
from flask import abort
from flask import current_app

from utils.x509 import ParameterError
from utils.x509 import X509Key
from utils.x509 import X509Cert
from utils.x509 import X509CertReq

from app.base import ApiResource


class X509Resource(ApiResource):
    endpoint = 'x509'
    url_prefix = '/generate'
    url_rules = {
        'index': {
            'rule': '/<component>'
        }
    }

    def _load_ca(self):
        config = current_app.config['USER_CONFIG']

        with open(config['ca_key']) as fh:
            key_pem = fh.read()
            ca_key = X509Key(key_pem)
        with open(config['ca_cert']) as fh:
            cert_pem = fh.read()
            ca_cert = X509Cert(cert_pem)

        return (ca_cert, ca_key)

    def get(self, component):
        if component != 'ca':
            abort(404, 'only the ca endpoint allows GET')

        ca_cert, ca_key = self._load_ca()
        return jsonify(certificate=ca_cert.pem)

    def post(self, component):
        if component not in ['csr', 'selfsigned', 'cert', 'sign', 'ca']:
            abort(404, 'unknown generate component: {}'.format(component))

        if component == 'ca':
            abort(405, 'ca endpoint only allowes GET')

        result = {}

        data = request.get_json()
        if not data:
            abort(400, 'no post data found')

        if component in ['selfsigned', 'cert']:
            key = X509Key()
            try:
                key.generate(**data['key'])
            except ParameterError as err:
                abort(400, 'error generating key: {}'.format(err))
            else:
                result['key'] = key.pem

        if component == 'csr':
            if 'key' not in data:
                abort(400, 'no key in post data. needed to create a new csr')
            key = X509Key(data['key'], data.get('password', None))

        if component == 'sign':
            if 'csr' not in data:
                abort(400, 'no csr found in post data')
            ca_cert, ca_key = self._load_ca()
            req = X509CertReq(data['csr'])
            cert = X509Cert()
            cert.generate(issuerKey=ca_key.key, issuerCert=ca_cert.cert, req=req.request)
            result['certificate'] = cert.pem

        if component in ['csr', 'selfsigned', 'cert']:
            req = X509CertReq()
            req.generate(
                key=key.key,
                name=data.get('names', []),
                extended_key_usage=data.get('extended_key_usage', []),
                subject_alt_names=data.get('subject_alt_names', []),
            )
            result['csr'] = req.pem

        if component == 'selfsigned':
            cert = X509Cert()
            cert.generate(issuerKey=key.key, issuerCert=False, req=req.request)
            result['certificate'] = cert.pem

        if component == 'cert':
            ca_cert, ca_key = self._load_ca()
            cert = X509Cert()
            cert.generate(issuerKey=ca_key.key, issuerCert=ca_cert.cert, req=req.request)
            result['certificate'] = cert.pem

        return jsonify(result)
