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


class Authenticate(object):
    def __init__(self, auth_header):
        self.auth_header = auth_header
        if self.auth_header:
            self.token = self.auth_header.split(' ')[1]
        else:
            self.token = None
        self.config = current_app.config['USER_CONFIG']

    def access(self, profile):
        if 'auth_key' not in profile:
            return True

        try:
            auth_key = self.config['auth_keys'][profile['auth_key']]
        except KeyError:
            return False

        if auth_key['type'] == 'plain':
            if auth_key['key'] == self.token:
                return True

        return False


class CertificateAuthority(object):
    def __init__(self, key_pem, cert_pem):
        self.key = X509Key(key_pem)
        self.cert = X509Cert(cert_pem)

    def sign(self, csr, days):
        req = X509CertReq(csr)
        cert = X509Cert()
        cert.generate(
            issuerKey=self.key.key,
            issuerCert=self.cert.cert,
            req=req.request,
            days=days
        )
        return cert


class X509Resource(ApiResource):
    endpoint = 'x509'
    url_prefix = '/generate'
    url_rules = {
        'index': {
            'rule': '/<endpoint>'
        }
    }

    def _load_ca(self):
        config = current_app.config['USER_CONFIG']
        with open(config['ca_key']) as fh:
            key_pem = fh.read()
        with open(config['ca_cert']) as fh:
            cert_pem = fh.read()

        return CertificateAuthority(key_pem, cert_pem)

    def _load_profile(self, profile):
        config = current_app.config['USER_CONFIG']
        if profile not in config['profiles']:
            abort(400, 'unknown profile: {}'.format(profile))
        return config['profiles'][profile]

    def get(self, endpoint):
        if endpoint != 'ca':
            abort(405, 'only the ca endpoint allows GET')

        ca = self._load_ca()
        return jsonify(certificate=ca.cert.pem)

    def post(self, endpoint):
        validation_map = {
            'csr': ['key', 'profile'],
            'selfsigned': ['profile'],
            'sign': ['csr', 'profile'],
            'cert': ['profile']
        }

        data = request.get_json()
        if endpoint not in validation_map:
            abort(404, 'unknown endpoint {}'.format(endpoint))
        for req_key in validation_map[endpoint]:
            if req_key not in data:
                abort(400, 'missing parameter {} for endpoint {}'.format(req_key, endpoint))

        profile = self._load_profile(data['profile'])
        auth = Authenticate(request.headers.get('Authorization'))
        if not auth.access(profile):
            abort(403, 'invalid authentication key')

        func = getattr(self, '_{}'.format(endpoint))

        return func(data, profile)

    def _csr(self, data, profile):
        key = X509Key(data['key'], data.get('password', None))
        req = X509CertReq()
        req.generate(
            key=key.key,
            name=data.get('names', []),
            profile=profile,
            subject_alt_names=data.get('subject_alt_names', []),
        )
        return jsonify(csr=req.pem)

    def _selfsigned(self, data, profile):
        key = X509Key()
        try:
            key.generate(**data['key'])
        except ParameterError as err:
            abort(400, 'error generating key: {}'.format(err))

        req = X509CertReq()
        req.generate(
            key=key.key,
            name=data.get('names', []),
            profile=profile,
            subject_alt_names=data.get('subject_alt_names', []),
        )

        cert = X509Cert()
        cert.generate(issuerKey=key.key, issuerCert=False, req=req.request, days=int(profile['expiry']))
        return jsonify(certificate=cert.pem, key=key.pem, csr=req.pem)

    def _cert(self, data, profile):
        key = X509Key()
        try:
            key.generate(**data['key'])
        except ParameterError as err:
            abort(400, 'error generating key: {}'.format(err))

        req = X509CertReq()
        req.generate(
            key=key.key,
            name=data.get('names', []),
            profile=profile,
            subject_alt_names=data.get('subject_alt_names', []),
        )

        ca = self._load_ca()
        cert = ca.sign(req.pem, int(profile['expiry']))
        return jsonify(certificate=cert.pem, key=key.pem, csr=req.pem)

    def _sign(self, data, profile):
        ca = self._load_ca()
        cert = ca.sign(data['csr'], days=int(profile['expiry']))
        return jsonify(certificate=cert.pem)
