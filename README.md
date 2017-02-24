# SSLApi

What a great and creative name for an SSL Api!

First of all: If you want an Api for singing and creating certificates, please be aware that there is [CFSSL](https://github.com/cloudflare/cfssl) which comes with an api as well and has already a large user base.

Why building something new then? Well, I needed functionality that is not (yet) in CFSSL. Currently it is impossible to create certificates with multiple Organizations or OrganizationlaUnits. Since I really needed that feature and because I really like writing stuff in python, I decided to get into cryptography 'n stuff.

## What can it do for me right now?

Right now you can use SSLApi to:

* Create RSA/DSA/ECDSA keys
* Create fully customizable Certificate Signing Requests (CSR)
* Create self-signed certificates
* Create a CA signed certificate/key bundle with one api call
* Sign you own CSR via the remote CA
* Get the remote CA certificate

## Whats planned for it?

That is planned for the nearest future in case my time management doesn't suck to hard:

* Bootstrap CA on first start
* Save generated certificates in a SQL backend (SQLalchemy)
* Get stored certificates from SQL Backend via serial or subject
* Some (good and usefull) kind of authentication

That is planned in case I get really bored:
* Certificate Revocation Lists (CRL)
* Support multiple CAs
* Server side profiles

## Requirements

You just need [Flask](http://flask.pocoo.org) and [Cryptography](https://cryptography.io):
```bash
$ pip install -r requirements.txt
```

## Configuration

Currently you need an already created CA (certificate and key) to run most endpoints. Just edit the `config.json` and enter the path to you ca files. That's it! Now you can run it:

```bash
$ ./sslapi.py
```

## Usage
