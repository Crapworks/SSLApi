#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import datetime
import ipaddress

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography import x509
from cryptography.x509.oid import _OID_NAMES


class ParameterError(Exception):
    pass


class X509Key(object):
    algorithm_parameter = {
        'dsa': ['key_size'],
        'rsa': ['key_size', 'public_exponent'],
        'ecdsa': ['curve']
    }

    def _validate_parameters(self, algorithm, **parameter):
        for key in parameter:
            if key not in self.algorithm_parameter[algorithm]:
                raise ParameterError('unkown parameter for {0} key: {1}'.format(algorithm, key))
        for key in self.algorithm_parameter[algorithm]:
            if key not in parameter:
                raise ParameterError('missing parameter for {0} key: {1}'.format(algorithm, key))

    def __init__(self, pem=None, password=None, backend=default_backend):
        if pem:
            self.key = serialization.load_pem_private_key(str(pem), password=password, backend=backend())

    def generate(self, algorithm, backend=default_backend, **parameter):
        if algorithm.lower() not in self.algorithm_parameter:
            raise ParameterError('unknown key algorithm: {0}'.format(algorithm.lower()))

        self._validate_parameters(algorithm, **parameter)

        if algorithm.lower() == 'rsa':
            primitive = rsa
        if algorithm.lower() == 'dsa':
            primitive = dsa
        if algorithm.lower() == 'ecdsa':
            primitive = ec

        self.key = primitive.generate_private_key(
            backend=backend(),
            **parameter
        )

    @property
    def pem(self):
        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )


class X509CertReq(object):
    def __init__(self, csr=None, backend=default_backend):
        if csr:
            self.request = x509.load_pem_x509_csr(str(csr), backend=backend())

    def generate(self, key, digest=hashes.SHA256(), backend=default_backend, name=[], extended_key_usage=[], subject_alt_names=[]):
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name(list(self._create_subject_name(name))))

        if extended_key_usage:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([self._get_oid(usage) for usage in extended_key_usage]), critical=False,
            )

        if subject_alt_names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([self._get_alt_name(alt) for alt in subject_alt_names]), critical=False,
            )

        self.request = builder.sign(
            key, digest, backend()
        )

    def _get_alt_name(self, alt_name):
        try:
            socket.inet_pton(socket.AF_INET, alt_name)
        except socket.error:
            return x509.DNSName(unicode(alt_name))
        else:
            return x509.IPAddress(ipaddress.IPv4Address(unicode(alt_name)))

    def _create_subject_name(self, name):
        for subject in name:
            for key, value in subject.iteritems():
                yield x509.NameAttribute(self._get_oid(key), unicode(value))

    def _get_oid(self, name):
        oid_mapping = {v: k for k, v in _OID_NAMES.iteritems()}
        return oid_mapping[name]

    @property
    def pem(self):
        return self.request.public_bytes(
            encoding=serialization.Encoding.PEM,
        )


class X509Cert(object):
    def __init__(self, cert=None, backend=default_backend):
        if cert:
            cert = x509.load_pem_x509_certificate(str(cert), backend=backend())

    def generate(self, issuerKey, issuerCert, req, days=365, digest=hashes.SHA256(), backend=default_backend):
        builder = x509.CertificateBuilder()
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))

        for extension in req.extensions:
            builder = builder.add_extension(extension.value, extension.critical)

        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(req.public_key()), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuerKey.public_key()), critical=False)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True,
        )
        builder = builder.subject_name(req.subject)
        builder = builder.public_key(req.public_key())

        if issuerCert is False:
            builder = builder.issuer_name(req.subject)
        else:
            builder = builder.issuer_name(issuerCert.subject)
        self.cert = builder.sign(issuerKey, digest, backend())

    @property
    def pem(self):
        return self.cert.public_bytes(
            encoding=serialization.Encoding.PEM,
        )
