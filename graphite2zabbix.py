#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
# graphite2zabbix
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; only version 2 of the License is applicable.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#
# Author: 
#     Lior Goikhburg <goikhburg at gmail.com >
#
# Description:
#     This program sends graphite metrics to zabbix
#
# Graphite
#     http://graphite.wikidot.com/
#
# Zabbix
#     http://www.zabbix.com/

__author__ = 'Lior Goikhburg'

import argparse
import logging
import json
import os
import re
import requests
import sys
import time
import urllib
from pyzabbix import ZabbixAPI
from zabbixtrapper import ZabbixTrapper


class Graphite(object):
    def __init__(self, host='localhost', port='80',
                 scheme='http', username='', password='', uri='/render'):
        self.uri = uri
        self.host = host
        self.port = port
        self.scheme = scheme
        self.session = requests.Session()

        if username:
            self.session.auth = (username, password)

        if self.scheme == 'https':
            self.session.verify = False

    def _get_data(self, params):
        """
        Request data from graphite.
        """

        request_uri = '?'.join([self.uri, params]) + '&format=json'
        url = "%s://%s:%s%s" % (self.scheme, self.host, self.port, request_uri)

        logger.debug("Requestig %s from Graphite API" % url)
        try:
            resp = self.session.get(url)
        except Exception as error:
            logger.error("Graphite API Error: %s" % error.message)
            return None

        if resp.status_code != 200:
            logger.error("Graphite API status code: %s (%s)" % (
                resp.status_code, resp.reason))
            return None
            
        return resp.json()

    def get_metrics(self, metrics, _from, until='now'):
        """
        From metrics list create uri params, add time period and request data
        """

        targets = '&target=' + '&target='.join([urllib.quote(metric)
                                                for metric in metrics])
        period = "from=%s&until=%s" % (_from, until)
        params = '&'.join([targets, period])

        return self._get_data(params)


def get_last_val(datapoints):
    """
    Get last (non-null) datapoint from list of graphite datapoints.
    If all values are null - return None
    """

    for datapoint in reversed(datapoints):
        if datapoint[0] is not None:
            return datapoint
    return None


def parse_zabbix_info(info):
    """
    Parses Zabbix trapper info line into a dict
    """

    info_parsed = {}
    for section in info.split(';'):
        key, delim, val = section.partition(':')
        if delim:
            info_parsed[key.strip()] = float(val)

    return info_parsed


def send_zabbix(traps):
    """
    Submit traps to Zabbix
    """

    try:
        ztrapper = ZabbixTrapper(config['zabbix']['trapper']['host'],
                                 config['zabbix']['trapper']['port'])
        trapper_result = ztrapper.send_traps(traps)
    except Exception as error:
        logger.error("Error sending traps to zabbix: %s" % error.message)
        return False

    response = trapper_result['response']
    info = trapper_result['info']

    if response != 'success':
        logger.error("Error sending traps to zabbix: %s" % info)
        return False

    logger.debug("Traps accepted (%s)" % info)
    info_parsed = parse_zabbix_info(info)
    if info_parsed['failed']:
        logger.warning("%i traps were not accepted by Zabbix" % info_parsed['failed'])
    
    return True


# extract metric name from zabbix key name
def extract_metric(zapi, item):
    """
    Extract metric name from key, resolve user macros if any
    """

    global item_cache
    key = item['key_']

    # resolve macros in key
    macros = zabbix_macro_re.findall(key)
    if macros:
        logger.debug("Key %s has user macros. Expansion is needed." % key)
        macro_dict = {element: '' for element in macros}

        # look up macros:
        # 1. host
        # 2. directly linked template (to host)
        # 3. a template linked to template etc, etc.
        process = True
        while process:
            hostid = item['hostid']
            try:
                user_macros = zapi.usermacro.get(output=['macro', 'value'],
                                                 hostids=[hostid])
            except Exception as error:
                logger.error("Zabbix API Error: %s", error.message)
                return ''

            for user_macro in user_macros:
                macro_name = user_macro['macro']
                macro_value = user_macro['value']
                if macro_name in macro_dict and not macro_dict[macro_name]:
                    logger.debug("Resolved User macro %s to %s" % (macro_name, macro_value))
                    macro_dict[macro_name] = macro_value

            parentid = item['templateid']
            if parentid == '0':
                process = False
            else:
                # fetch item from cache, or request from api
                if parentid not in item_cache:
                    try:
                        item_cache[parentid] = zapi.item.get(output=['hostid', 'templateid'],
                                                             itemids=[parentid])[0]
                    except Exception as error:
                        logger.error("Zabbix API Error: %s", error.message)
                        return ''
                item = item_cache[parentid]

        for macro_name, macro_value in macro_dict.iteritems():
            if not macro_value:
                logger.warning("Failed to resolve a user macro %s in key %s - skipping it." %
                               (macro_name, key))
                return ''
            key = key.replace(macro_name, macro_value)

    # extract metric part
    match = metric_name_re.search(key)
    metric = ''
    if match and len(match.groups()) == 1:
        metric = match.group(1)
    return metric


def main():
    # Connect to Zabbix API
    logger.debug('Connecting to Zabbix API')
    zapi = ZabbixAPI(server="%s://%s:%s%s" % (config['zabbix']['api']['scheme'],
                                              config['zabbix']['api']['host'],
                                              config['zabbix']['api']['port'],
                                              config['zabbix']['api']['uri']))

    if config['zabbix']['api']['scheme'] == 'https':
        zapi.session.verify = False

    try:
        zapi.login(config['zabbix']['api']['username'],
                   config['zabbix']['api']['password'])
    except Exception as error:
        logger.error("Login to Zabbix Error: %s", error.message)
        return False

    # Query Zabbix to retrieve only hosts that match the following criteria
    # 1. Host is being monitored
    # 2. Host has items 
    # Data returned will contain:
    # 1 host ids
    # 2 host names
    logger.debug('Looking for hosts in Zabbix')
    try:
        zhosts = zapi.host.get(output='shorten',
                               monitored_hosts=True,
                               with_items=True,
                               )
    except Exception as error:
        logger.error("Zabbix API Error: %s", error.message)
        return False

    if not zhosts:
        logger.error('No configured Zabbix hosts found')
        return False

    hostids = [host_entry['hostid'] for host_entry in zhosts]
    logger.debug("Found %s relevant hosts" % len(zhosts))

    # Query Zabbix to retrieve only items which match the following criteria
    # 1. Item is of the 'zabbix trapper' (2) type
    # 2. The key_ name begins with config['zabbix']['key_prefix']
    # 3. The item belongs to one of the zhosts (this will rule out items linked to templates).
    # Data returned will contain:
    # 1. Item id
    # 2. key_ name
    # 3. host id of the linked host
    # 4. templateid id of the parent ITEM
    logger.debug('Looking for zabbix items')
    try:
        zitems = zapi.item.get(output=['key_', 'hostid', 'templateid'],
                               filter={'type': 2},
                               search={'key_': config['zabbix']['key_prefix']},
                               startSearch=True,
                               hostids=hostids,
                               selectHosts=['name'])
    except Exception as error:
        logger.error("Zabbix API Error: %s", error.message)
        return False

    if not zitems:
        logger.error('No configured Zabbix items found')
        return False

    logger.debug("Found %s relevant items" % len(zitems))

    # Create dict of dicts of zabbix data (only missing values)
    zabbix_data = {}
    for item in zitems:
        fqdn = item['hosts'][0]['name']

        hostname = fqdn.partition('.')[0]

        logger.debug("Processing Key: %s:%s" % (fqdn, item['key_']))
        metric = extract_metric(zapi, item)
        if not metric:
            logger.warning("Incorrectly configured key %s" % item['key_'])
            continue

        metric = "%s.%s" % (hostname, metric)
        zabbix_data[metric] = {'host': fqdn, 'key': item['key_'], 'clock': int(time.time())}

    graphite = Graphite(host=config['graphite']['host'],
                        port=config['graphite']['port'],
                        scheme=config['graphite']['scheme'],
                        username=config['graphite']['username'],
                        password=config['graphite']['password'],
                        uri=config['graphite']['uri'])

    logger.debug('Requesting metrics from graphite')
    targets = graphite.get_metrics(zabbix_data.keys(), config['graphite']['period'])

    if not targets:
        logger.error('No metrics matching configured zabbix keys found in graphite')
        return False

    logger.debug("Received %s metrics" % len(targets))
    if len(targets) < len(zabbix_data):
        logger.warning('Graphite returned less metrics, than requested')

    # reformat graphite data into a dict with metric_name -> [[datapoints]]
    graphite_metrics = {}
    for target in targets:
        metric_name = target['target']
        graphite_metrics[metric_name] = target['datapoints']

    # Build traps list, while checking for all metric configured in zabbix.
    # If metric exists in graphite checks if its last value is null
    traps = []
    for metric in zabbix_data.keys():
        if metric not in graphite_metrics.keys():
            logger.warning("Metric %s doesn't exist in graphite" % metric)
            continue
        else:
            last_val = get_last_val(graphite_metrics[metric])
            if not last_val:
                logger.warning("No data for metric %s " % metric)
                continue
            else:
                zabbix_data[metric].update({'value': last_val[0]})
                traps.append(zabbix_data[metric])

    logger.debug("Sending %s traps to Zabbix" % len(traps))
    return send_zabbix(traps)

if __name__ == '__main__':
    config = {
        'zabbix': {
            'key_prefix': 'graphite.metric',
            'api': {
                'host': 'zabbix.host.com',
                'port': '443',
                'scheme': 'https',
                'username': 'api-username',
                'password': 'api-password',
                'uri': '/'
            },
            'trapper': {
                'host': 'zabbix.trapper.host.com',
                'port':  10051,
                'status_key': 'graphite2zabbix.status'
            }
        },
        'graphite': {
            'host': 'graphite.host.com',
            'port': '443',
            'scheme': 'https',
            'username': 'graphite-user',
            'password': 'graphite-password',
            'uri': '/render',
            'period': '-3minutes'
        }
    }

    metric_name_re = re.compile(r'\[([^\[]+)\]')
    zabbix_macro_re = re.compile(r'{\$[^}]+}')
    item_cache = {}

    parser = argparse.ArgumentParser(prog=os.path.basename(__file__),
                                     description='Graphite 2 Zabbix Bridge',
                                     epilog="Example: %(prog)s -v")
    parser.add_argument('-v', '--verbose', help='Verbose', action='count')
    args = parser.parse_args()

    LogLevel = logging.WARNING
    if args.verbose:
        LogLevel = logging.DEBUG

    logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s: %(message)s',
                        datefmt='%F %H:%M:%S', level=logging.WARNING)
    logger = logging.getLogger(os.path.basename(__file__))
    logger.setLevel(LogLevel)

    exit_status = 0 if main() else 1

    if 'status_key' in config['zabbix']['trapper'] and config['zabbix']['trapper']['status_key']:
        # send program status to zabbix
        logger.debug("Sending program status <%s> to Zabbix" % exit_status)
        result = send_zabbix([{'host': config['zabbix']['trapper']['host'],
                               'key': config['zabbix']['trapper']['status_key'],
                               'value': exit_status,
                               'clock': int(time.time())}])

        exit_status = 0 if result and exit_status == 0 else 1

    sys.exit(exit_status)
