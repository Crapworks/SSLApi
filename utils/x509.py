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
    """Representation of a private key

    Without any arguments this class just creates an empty instance. Provide a
    PEM encoded private key and it will load and decrypt it (if ``password``
    is provided as well).

    Args:
        pem (:obj:`str`, optional): The PEM encoded private key
        password (:obj:`str`, optional): Password in case the PEM is enrypted
        backend (:obj:`backend`, optional): Specify a backend to use
    """

    algorithm_parameter = {
        'dsa': ['key_size'],
        'rsa': ['key_size', 'public_exponent'],
        'ecdsa': ['curve']
    }

    def __init__(self, pem=None, password=None, backend=default_backend):
        if pem:
            self.key = serialization.load_pem_private_key(str(pem), password=password, backend=backend())

    def _validate_parameters(self, algorithm, **parameter):
        """Validate key generation parameters"""

        for key in parameter:
            if key not in self.algorithm_parameter[algorithm]:
                raise ParameterError('unkown parameter for {0} key: {1}'.format(algorithm, key))
        for key in self.algorithm_parameter[algorithm]:
            if key not in parameter:
                raise ParameterError('missing parameter for {0} key: {1}'.format(algorithm, key))

    def _get_curve(self, name):
        """Map curve names to EllipticCurve objects"""
        if name not in ec._CURVE_TYPES:
            raise ParameterError('unknown curve type: {}'.format(name))
        return ec._CURVE_TYPES[name]

    def generate(self, algorithm, backend=default_backend, **parameter):
        """Generate a private key

        Different algorithms need different parameters. DSA for example
        just needs the ``key_size`` parameter, while ECDSA needs the ``curve``
        parameter that specifies which elliptic curve algorithm should be used.

        Args:
            algorith (str): Algorith to use (dsa, rsa or ecdsa)
            **parameter: key generation parameter
        """

        if algorithm.lower() not in self.algorithm_parameter:
            raise ParameterError('unknown key algorithm: {0}'.format(algorithm.lower()))

        self._validate_parameters(algorithm, **parameter)

        if algorithm.lower() == 'rsa':
            primitive = rsa
        if algorithm.lower() == 'dsa':
            primitive = dsa
        if algorithm.lower() == 'ecdsa':
            primitive = ec
            parameter['curve'] = self._get_curve(parameter['curve'])

        self.key = primitive.generate_private_key(
            backend=backend(),
            **parameter
        )

    @property
    def pem(self):
        """str: Return PEM encoded unencryped key"""

        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )


class X509CertReq(object):
    """Representation of a X509 Certificate Signing Request

    Without any arguments this class just creates an empty instance. Provide a
    PEM encoded CSR and it will load and it.

    Args:
        pem (:obj:`str`, optional): The PEM encoded CSR
        backend (:obj:`backend`, optional): Specify a backend to use
    """

    def __init__(self, csr=None, backend=default_backend):
        if csr:
            self.request = x509.load_pem_x509_csr(str(csr), backend=backend())

    def generate(self, key, profile, digest=hashes.SHA256(), backend=default_backend, name=[], subject_alt_names=[]):
        """Generate a Certificate Signing Request (CSR)

        The CSR needs to be signed by a private key using a digest (defaults
        to SHA256). The ``name`` argument is a list of dictionaries in the
        form of ``{"commonName": "foobar.com"}``  The names get mapped to
        X509 OIDS. Short forms are not supported yet.

        Args:
            key (obj): Private key instance that signs the CSR
            profile (dict): profile dictionary defining certificate options
            digest (:obj: `digest`, optional): Digest instance used for signing
            backend (:obj:`backend`, optional): Specify a backend to use
            name (:obj:`list`, optional): list of dict of X509 Subjects
            subject_alt_names (:obj:`list`, optional): list of SubjectAlternativeNames
        """

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name(list(self._create_subject_name(name))))

        if 'extended_key_usage' in profile:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([self._get_oid(usage) for usage in profile['extended_key_usage']]), critical=False,
            )

        if subject_alt_names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([self._get_alt_name(alt) for alt in subject_alt_names]), critical=False,
            )

        constraints = {'ca': False, 'path_length': None}
        constraints.update(profile.get('basic_constraints', {}))
        builder = builder.add_extension(x509.BasicConstraints(**constraints), critical=True)

        usage = [
            'digital_signature', 'content_commitment', 'key_encipherment', 'data_encipherment',
            'key_agreement', 'key_cert_sign', 'crl_sign', 'encipher_only', 'decipher_only'
        ]
        usage = dict.fromkeys(usage, False)
        usage.update(dict.fromkeys(profile.get('key_usage', []), True))
        builder = builder.add_extension(x509.KeyUsage(**usage), critical=True)

        self.request = builder.sign(
            key, digest, backend()
        )

    def _get_alt_name(self, alt_name):
        """Get instances of X509 Names according to their type"""
        try:
            socket.inet_pton(socket.AF_INET, alt_name)
        except socket.error:
            return x509.DNSName(unicode(alt_name))
        else:
            return x509.IPAddress(ipaddress.IPv4Address(unicode(alt_name)))

    def _create_subject_name(self, name):
        """Get list of X509 NameAttributes"""
        for subject in name:
            for key, value in subject.iteritems():
                yield x509.NameAttribute(self._get_oid(key), unicode(value))

    def _get_oid(self, name):
        """Map names to corresonding OID attributes"""
        oid_mapping = {v: k for k, v in _OID_NAMES.iteritems()}
        return oid_mapping[name]

    @property
    def pem(self):
        """str: PEM encoded CSR"""
        return self.request.public_bytes(
            encoding=serialization.Encoding.PEM,
        )


class X509Cert(object):
    """Representation of a X509 Certificate

    Without any arguments this class just creates an empty instance. Provide a
    PEM encoded Certificate and it will load and it.

    Args:
        pem (:obj:`str`, optional): The PEM encoded Certificate
        backend (:obj:`backend`, optional): Specify a backend to use
    """

    def __init__(self, cert=None, backend=default_backend):
        if cert:
            self.cert = x509.load_pem_x509_certificate(str(cert), backend=backend())

    def generate(self, issuerKey, issuerCert, req, days=365, digest=hashes.SHA256(), backend=default_backend):
        """Generate a Certificate

        This will sign a CSR with the provided IssuerKey and Issuer Cert.

        Args:
            issuerKey (obj): Private that should sign the certificate
            issuerCert (obj): Issuer certificate
            req (obj): Certificate Signing Request to sign
            days (:obj:`int`, optinal): Number of days before the certificate expires
            digest (:obj: `digest`, optional): Digest instance used for signing
            backend (:obj:`backend`, optional): Specify a backend to use
        """

        builder = x509.CertificateBuilder()
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))

        for extension in req.extensions:
            builder = builder.add_extension(extension.value, extension.critical)

        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(req.public_key()), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuerKey.public_key()), critical=False)
        builder = builder.subject_name(req.subject)
        builder = builder.public_key(req.public_key())

        if issuerCert is False:
            builder = builder.issuer_name(req.subject)
        else:
            builder = builder.issuer_name(issuerCert.subject)
        self.cert = builder.sign(issuerKey, digest, backend())

    @property
    def pem(self):
        """str: PEM encoded Certificate"""
        return self.cert.public_bytes(
            encoding=serialization.Encoding.PEM,
        )
