#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import sys
import json
import argparse

from app import create_app
from app.base import BootstrapCA

app = create_app()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', default=8888)
    parser.add_argument('-b', '--bind', default='0.0.0.0')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-x', '--bootstrap', default=None)

    args = parser.parse_args()

    if args.bootstrap:
        bootstrap = BootstrapCA(args.bootstrap)
        print('* generating ca from {}...'.format(args.bootstrap), file=sys.stderr)
        print(json.dumps(bootstrap.generate()))
    else:
        app.run(host=args.bind, port=args.port, debug=args.debug)
