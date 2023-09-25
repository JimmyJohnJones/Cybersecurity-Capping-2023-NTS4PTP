#! /usr/bin/python
from __future__ import division, print_function, unicode_literals

import time
import math
import re
import binascii

NTP_TS_EPOCH_OFFSET = 2208988800

# convert ntp short val to seconds
def ntp_short_to_seconds(ntp_short):
    return ntp_short / 2.0 ** 16

# convert NTP to epoch time stamp
def ntp_ts_to_epoch(ntp_ts):
    return ntp_ts / 2.0**32 - NTP_TS_EPOCH_OFFSET

# convert NTP to ISO time stamp
def ntp_ts_to_iso(ntp_ts):
    t = ntp_ts_to_epoch(ntp_ts)
    s = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t))
    s += "%.6fZ" % (t - math.floor(t))
    return s

# convert epoch to NTP time stamp
def epoch_to_ntp_ts(t):
    return int((t + NTP_TS_EPOCH_OFFSET) * 2.0**32)

# convert ascii to hex
def hexlify(d, n = 4):
    return ' '.join([ binascii.hexlify(d[i:i+n]).decode('ASCII')
                      for i in range(0, len(d), n) ])

# clean characters in expression 
def sanitize(s):
    return re.sub('[^-.A-Za-z0-9]', '?', s)

# write client.ini file for NTP client
def write_client_ini(client):
    import configparser
    config = configparser.RawConfigParser()
    config.read('client.ini')
    if not config.has_section('ntpv4'):
        config.add_section('ntpv4')
    config.set('ntpv4', 'server', client.ntpv4_server)
    config.set('ntpv4', 'port', "%u" % client.ntpv4_port)
    if not config.has_section('keys'):
        config.add_section('keys')
    config.set('keys', 'c2s', binascii.hexlify(client.c2s_key).decode('ascii'))
    config.set('keys', 's2c', binascii.hexlify(client.s2c_key).decode('ascii'))
    config.remove_section('cookies')
    config.add_section('cookies')
    for k, v in enumerate(client.cookies):
        config.set('cookies', str(k), binascii.hexlify(v).decode('ascii'))
    with open('client.ini', 'w') as f:
        config.write(f)
