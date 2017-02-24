#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

from app import create_app

app = create_app()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', default=8888)
    parser.add_argument('-b', '--bind', default='0.0.0.0')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-x', '--bootstrap', default=None)

    args = parser.parse_args()

    app.run(host=args.bind, port=args.port, debug=args.debug)
