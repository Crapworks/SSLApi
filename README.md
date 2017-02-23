# SSLApi

What a great and creative name for an SSL Api!

First of all: If you want an Api for singing and creating certificates, please be aware that there is [CFSSL](https://github.com/cloudflare/cfssl) which comes with an api as well and has already a large user base.

Why building something new then? Well, I needed functionality that is not (yet) in CFSSL. Currently it is impossible to create certificates with multiple Organizations or OrganizationlaUnits. Since I really needed that feature and because I really like writing stuff in python, I decided to get into cryptography 'n stuff.


