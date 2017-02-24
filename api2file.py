#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--prefix', default='remote')
    args = parser.parse_args()

    file_map = {
        'certificate': '',
        'csr': '-csr',
        'key': '-key'
    }

    response = json.load(sys.stdin)

    for pem_type, postfix in file_map.iteritems():
        if pem_type in response:
            with open('{}{}.pem'.format(args.prefix, postfix), 'w') as fh:
                fh.write(response[pem_type])

if __name__ == '__main__':
    main()
