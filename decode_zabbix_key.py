#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 

import base64
import sys

def decode_base64(string):
    """
    Decode base64 url safe string, add padding if needed

    """

    missing_padding = 4 - len(string) % 4
    if missing_padding:
        string += '=' * missing_padding
    return base64.urlsafe_b64decode(str(string))

if len(sys.argv) < 2 or '-h' in sys.argv:
    print "Example: decode_zabbix_key.py encoded_zabbix_key_name\n"
    sys.exit()

print decode_base64(sys.argv[1])
