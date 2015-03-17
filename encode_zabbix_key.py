#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 

import base64
import sys

if len(sys.argv) < 2 or '-h' in sys.argv:
    print "Example: encode_zabbix_key.py zabbix_key_name\n"
    sys.exit()

print base64.urlsafe_b64encode(sys.argv[1]).rstrip("=")
