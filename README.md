# SSLApi

What a great and creative name for an SSL Api!

First of all: If you want an Api for singing and creating certificates, please be aware that there is [CFSSL](https://github.com/cloudflare/cfssl) which comes with an api as well and has already a large user base.

Why building something new then? Well, I needed functionality that is not (yet) in CFSSL. Currently it is impossible to create certificates with multiple Organizations or OrganizationlaUnits. Since I really needed that feature and because I really like writing stuff in python, I decided to get into cryptography 'n stuff.

## Quickstart

1. Clone this repository

    ```bash
    $ git clone https://github.com/Crapworks/SSLApi.git
    $ cd SSLApi
    ```

2. Install the dependencies

    ```bash
    $ pip inststall -r requirements.txt
    ```

3. Edit `example-ca-csr.json` (This will become your CA) and run the following command

    ```bash
    $ ./sslapi.py --bootstrap example-ca-csr.json | ./api2file.py --prefix ca
    ```

4. Check `config.json` to see if the filenames are matching (if you used the exact command above they should match)

5. Of course you can use your own CA if you already have one. Just enter the path to your CA certificate and key into `config.json` and make sure these files are readable for the user you want SSLApi to run under

6. Start it up!

    ```bash
    $ ./sslapi.py
    ```

7. Create your first certificate and key via SSLApi

    ```bash
    $ cat mycert.json
    {
        "profile": "server",
        "key": {
            "algorithm": "dsa", 
            "key_size": 2048
        }, 
        "names":[
            {"commonName": "foobar.com"}
        ],
        "extended_key_usage": ["serverAuth"],
        "subject_alt_names": ["barfoo.com"]
    }

    $ curl -H 'content-type: application/json' -d@mycert.json localhost:8888/v1/x509/cert | ./api2file.py --prefix certfoo
    ```

8. Verify that everything looks good:

    ```bash
    $ openssl x509 -in certfoo.pem -text
    ```

9. Profit!!1

## What can it do for me right now?

Right now you can use SSLApi to:

* Create RSA/DSA/ECDSA keys
* Create fully customizable Certificate Signing Requests (CSR)
* Create self-signed certificates
* Create a CA signed certificate/key bundle with one api call
* Bootstrap CA to sign with
* Sign you own CSR via the remote CA
* Get the remote CA certificate
* Server side profiles
* (Very) simple, token based authentication

## Whats planned for it?

That is planned for the nearest future in case my time management doesn't suck to hard:

* Save generated certificates in a SQL backend (SQLalchemy)
* Get stored certificates from SQL Backend via serial or subject

That is planned in case I get really bored:
* Certificate Revocation Lists (CRL)
* Support multiple CAs
* JWT authentication support

## Requirements

You just need [Flask](http://flask.pocoo.org) and [Cryptography](https://cryptography.io):
```bash
$ pip install -r requirements.txt
```

## Configuration

Currently you need an already created CA (certificate and key) to run most endpoints. Just edit the `config.json` and enter the path to you ca files. That's it! Now you can run it:

```bash
$ ./sslapi.py
 * Running on http://0.0.0.0:8888/ (Press CTRL+C to quit)
```

## Usage

TBD
