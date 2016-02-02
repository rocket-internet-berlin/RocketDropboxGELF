#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A Dropbox-to-GELF audit logs injector
:copyright: (c) 2015 Rocket Internet SE
:license: MIT, see LICENSE for more details.
"""

__author__ = "Luca Bruno"
__email__ = "luca.bruno@rocket-internet.de"

import configparser
import json
import logging
import sys
import time

import iso8601
from pygelf import GelfTcpHandler, GelfUdpHandler, GelfTlsHandler
import requests

API_ENDPOINT = 'https://api.dropbox.com/1/team/log/get_events'
_dg_debug = False


def dropbox_to_graylog(token, start_ts, end_ts, url=API_ENDPOINT,
                       limit=None, handler=None):
    logger = logging.getLogger('Dropbox-audit')
    injected = 0
    has_more = True
    cursor = None
    headers = {'Authorization': 'Bearer {}'.format(token),
               'Content-Type': 'application/json'}
    postdata = {'start_ts': int(start_ts),
                'end_ts': int(end_ts)}
    if isinstance(limit, int):
        postdata['limit'] = str(limit)
    # Fetch paginated entries
    while has_more:
        postdata.pop('cursor', None)
        if cursor:
            postdata['cursor'] = cursor
        http_resp = requests.post(url, headers=headers,
                                  data=json.dumps(postdata))
        if _dg_debug:
            import pprint
            pprint.pprint(http_resp.json())
        if http_resp.status_code != 200:
            print(http_resp.text)
            sys.exit('API call failed')
            logging.shutdown()
        json_resp = http_resp.json()
        events = json_resp.get('events', [])
        has_more = json_resp.get('has_more', False)
        if has_more:
            cursor = json_resp.get('cursor', None)
        for line in events:
            injected += 1
            if handler:
                time = line.get('time', '')
                user = line.get('email', '')
                ip = line.get('ip_address', '')
                etype = line.get('event_type', '')
                f = {'_dropbox-ip': '{}'.format(ip),
                     '_dropbox-user': '{}'.format(user),
                     '_dropbox-time': '{}'.format(time),
                     '_dropbox-type': '{}'.format(etype)}
                if time:
                    ts = iso8601.parse_date(time)
                    f['timestamp'] = int(ts.strftime("%s"))
                handler.additional_fields.update(f)
            logger.warning(json.dumps(line))
    return injected

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('Usage: %s configfile.ini' % sys.argv[0])
    # Read parameters from INI file
    cfg_p = configparser.ConfigParser()
    if not cfg_p.read(sys.argv[1]):
        sys.exit('Unable to read config file')
    config = cfg_p[cfg_p.sections()[0]]
    token = config.get('token')
    limit = config.get('limit', None)
    timespan = int(config.get('timespan', 3600))  # in seconds
    end_ts = time.time() * 1000
    start_ts = end_ts - (timespan * 1000)
    _dg_debug = bool(config.get('debug', None))
    # Setup GELF logger
    h = None
    gelf_host = config.get('host', '127.0.0.1')
    gelf_port = int(config.get('port', 11201))
    gelf_protocol = config.get('protocol', 'udp')  # (tcp|udp|tls)
    gelf_source = config.get('source_label', 'Dropbox-audit')
    if gelf_protocol == 'udp':
        h = GelfUdpHandler(host=gelf_host, port=gelf_port,
                           source=gelf_source)
    elif gelf_protocol == 'tcp':
        h = GelfTcpHandler(host=gelf_host, port=gelf_port,
                           source=gelf_source)
    elif gelf_protocol == 'tls':
        tls_cafile = config.get('tls_cafile',
                                '/etc/ssl/certs/ca-certificates.crt')
        h = GelfTlsHandler(host=gelf_host, port=gelf_port,
                           source=gelf_source, validate=True,
                           ca_certs=tls_cafile)
    else:
        sys.exit('Unknown protocol')
    logger = logging.getLogger()
    logger.addHandler(h)
    # Import audit entries
    n = dropbox_to_graylog(token, start_ts, end_ts, limit=limit, handler=h)
    h.flush()
    logging.shutdown()
    if _dg_debug:
        print("Injected {} entries to {}".format(n, gelf_host))
