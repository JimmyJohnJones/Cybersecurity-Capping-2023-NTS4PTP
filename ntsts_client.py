#! /usr/bin/python3
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import os
import sys
import struct
import socket
import rfc7822
import binascii
import random

import aes_siv

from ntp import NTPPacket, NTPExtensionField,  NTPExtensionFieldType
import ntp
from nts import NTSClientPacketHelper, NTSCookie
from constants import *

def randbytes(n):
    return bytearray(random.getrandbits(8) for _ in range(n))

# NTP Client
class NTSTSClient(object):
    def __init__(self):
        self.host = None
        self.port = None
        self.ipv4_only = False
        self.ipv6_only = False

        self.c2s_key = None
        self.s2c_key = None
        self.cookies = None

        self.debug = 0
        self.fuzz = 0
        self.fuzzed = 0
        self.uidsize = None

        self.infos = []
        self.errors = []
        self.warnings = []

    # generate unique identifier for extension field
    def add_unique_identifier(self, req):
        n = 32

        if self.uidsize is not None:
            n = self.uidsize
            print("forcing UID length %d" % n)
        elif self.fuzz & 0x1 and random.random() < 0.3:
            n = random.randrange(128) * 4
            print("fuzzing: random UID length %d" % n)
            self.fuzzed |= 0x01

        if n < 32:
            self.failure_expected = True

        unique_identifier = os.urandom(n)

        field = NTPExtensionField(
            NTPExtensionFieldType.Unique_Identifier,
            unique_identifier)
        req.ext.append(field)

        if self.uidsize is not None:
            field.force_size = True

        return unique_identifier

    # open communication to NTP server
    def communicate(self):
        self.failure_expected = False
        self.failure_allowed = False

        # open socket
        if self.ipv6_only:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(1)

        # get first cookie from list
        cookie = self.cookies[0]
        del self.cookies[0]

        # generate request with NTS extension field
        req = NTSClientPacketHelper()
        req.debug = self.debug
        req.transmit_timestamp = struct.unpack('Q', os.urandom(8))[0]

        if (self.fuzz & 0x2) and random.random() < 0.3:
            print("fuzzing: skipping unique identifier")
            unique_identifier = None
            self.fuzzed |= 0x02
            self.failure_expected = True

        else:
            unique_identifier = self.add_unique_identifier(req)

            if (self.fuzz & 0x4) and random.random() < 0.3:
                print("fuzzing: adding one more unique identifier")
                self.add_unique_identifier(req)
                self.failure_expected = True

            elif (self.fuzz & 0x8) and random.random() < 0.3:
                print("fuzzing: duplicating unique identifier")
                req.ext.append(req.ext[-1])
                self.add_unique_identifier(req)
                self.failure_expected = True

        if (self.fuzz & 0x10) and random.random() < 0.3:
            print("fuzzing: skipping cookie")
            self.failure_expected = True
        else:
            if (self.fuzz & 0x20) and random.random() < 0.3:
                n = 1 + random.randrange(1024)
                print("fuzzing: adding %d bytes of random data to cookie" % n)
                self.failure_expected = True
            else:
                n = 0
            req.ext.append(NTPExtensionField(
                NTPExtensionFieldType.NTS_Cookie,
                cookie + randbytes(n)))

            if (self.fuzz & 0x40) and random.random() < 0.1:
                print("fuzzing: duplicating cookie")
                req.ext.append(req.ext[-1])
                self.failure_expected = True

        while (self.fuzz & 0x80) and random.random() < 0.3:
            t = random.randrange(65536)
            n = random.randrange(1024)
            print("fuzzing: adding field 0x%04x of length %d" % (t,n))
            req.ext.append(NTPExtensionField(t, randbytes(n)))
            self.failure_allowed = True

        req.pack_key = self.c2s_key
        req.enc_ext = [ ]

        while (self.fuzz & 0x100) and random.random() < 0.3:
            t = random.randrange(65536)
            n = random.randrange(1024)
            print("fuzzing: adding encrypted field 0x%04x of length %d" % (t,n))
            req.enc_ext.append(NTPExtensionField(t, randbytes(n)))
            self.failure_allowed = True

        if self.fuzz & 0x200 and len(self.cookies) > 1:
            n = random.randrange(len(self.cookies)-1)
            if n:
                print("fuzzing: throwing away %d cookie placeholders" % n)
                del self.cookies[-n:]

        nr_placeholders = 8 - len(self.cookies) - 1
        for i in range(nr_placeholders):
            placeholder = bytes(bytearray(len(cookie)))

            if (self.fuzz & 0x400) and random.random() < 0.3 / nr_placeholders:
                n = 4 + 4 * random.randrange(256)
                placeholder += randbytes(n)
                print("fuzzing: adding %d bytes of random data to cookie placeholder %d" % (n, i))
                self.failure_expected = True
            elif (self.fuzz & 0x800) and random.random() < 0.3 / nr_placeholders:
                n = 4 + 4 * random.randrange(len(placeholder)/4-1)
                print("fuzzing: cutting %d bytes off end of cookie placeholder %d" % (n, i))
                placeholder = placeholder[:-n]
                self.failure_expected = True

            if len(placeholder) != len(cookie):
                print("fuzzing: placeholder length %d" % (len(placeholder)))

            req.ext.append(NTPExtensionField(NTPExtensionFieldType.NTS_Cookie_Placeholder, placeholder))

        # TODO add extra cookie placeholders

        if (self.fuzz & 0x1000):
            print("fuzzing: shuffling order of extension fields")
            random.shuffle(req.ext)

        # pack request into buffer and send
        buf = req.pack()

        if self.debug:
            try:
                print(NTPPacket.unpack(buf))
            except Exception as e:
                print("Failed to unpack request", e)
            print()

        if 0:
            print(NTSServerPacket.unpack(buf, unpack_key = self.c2s_key))
            print()

        if 1 and self.debug:
            s = (''.join([ '%02x' % b for b in buf ]))
            print(s)

        nts_addr = (self.host, self.port)
        if self.debug:
            print(nts_addr)
        sock.sendto(buf, nts_addr)

        # receive response
        try:
            data, addr = sock.recvfrom(65536)
        except socket.timeout as e:
            if self.failure_allowed or self.failure_expected:
                self.infos.append(e)
            else:
                self.errors.append(e)
            return

        # take in resp
        try:
            resp = NTSClientPacketHelper.unpack(data, unpack_key = self.s2c_key)
            if self.debug:
                print(resp)
        except ValueError as e:
            if len(unique_identifier) > 100:
                # Bug in FPGA, it sends strange responses sometimes when the UID field length is big.  Or try uidsize 308 or 500 which will get a response with total garbage
                self.warnings.append(e)
            else:
                self.errors.append(e)
            return

        # check resp for all the necessary fields
        if resp.origin_timestamp != req.transmit_timestamp:
            s = "transmitted origin and received transmit timestamps do not match"
            self.errors.append(s)

        if resp.unique_identifier is None:
            s = "Warning: no unique identifier returned"
            if unique_identifier is None or len(unique_identifier) < 32:
                self.infos.append(s)
            else:
                self.errors.append(s)

        elif unique_identifier is None:
            s = "Warning: unique identifier returned when there should be none"
            self.errors.append(s)

        elif len(resp.unique_identifier) != len(unique_identifier):
            s = "transmitted and received unique identifier lengths do not match %s %s" % (len(resp.unique_identifier), len(unique_identifier))
            if len(unique_identifier) < 32:
                self.infos.append(s)
            else:
                self.errors.append(s)
        elif resp.unique_identifier != unique_identifier:
            s = "transmitted and received unique identifiers do not match"
            if unique_identifier is None or len(unique_identifier) < 32:
                self.infos.append(s)
            else:
                self.errors.append(s)
        else:
            if unique_identifier is None or len(unique_identifier) < 32:
                s = "transmitted and received unique identifiers match when they shouldn't"
                self.errors.append(s)

        if self.debug:
            print("nts_cookies", len(resp.nts_cookies))
            if resp.enc_ext is None:
                print("enc_ext", None)
            else:
                print("enc_ext", len(resp.enc_ext))
            if resp.unauth_ext is None:
                print("unath_ext", None)
            else:
                print("unath_ext", len(resp.unauth_ext))

        # add NTS cookies to list of cookies
        self.cookies.extend(resp.nts_cookies)

        if resp.stratum == 0:
            s = "got kiss of death"
            if self.failure_allowed or self.failure_expected:
                self.infos.append(s)
            else:
                self.errors.append(s)
        else:
            if self.failure_expected:
                self.errors.append("succeeded when failure expected")

        if self.fuzz and not self.errors:
            print("success")

def main():
    # initialize NTP/NTS Time Stamp client
    client = NTSTSClient()

    try:
        import configparser
    except ImportError:
        import ConfigParser as configparser

    # get config from client.ini file
    config = configparser.RawConfigParser()
    config.read('client.ini')

    client.host = config.get('ntpv4', 'server').strip()
    client.port = int(config.get('ntpv4', 'port'))

    # get config from command line
    argi = 1

    while argi < len(sys.argv) and sys.argv[argi].startswith('-'):
        opts = sys.argv[argi][1:]
        argi += 1
        for o in opts:
            if o == '4':
                client.ipv4_only = True
            elif o == '6':
                client.ipv6_only = True
            elif o == 'd':
                client.debug += 1
            elif o == 'z':
                client.fuzz = int(sys.argv[argi], 16)
                argi += 1
            elif o == 'u':
                client.uidsize = int(sys.argv[argi])
                argi += 1
            else:
                print("unknown option -%s" % repr(o), file = sys.stderr)
                sys.exit(1)

    random.seed()

    if len(sys.argv) not in [ argi, argi + 2 ]:
        print("Usage: python [-46] nts-client.py <host> <port>",
              file=sys.stderr)
        sys.exit(1)

    if client.ipv4_only and client.ipv6_only:
        print("Error: both -4 and -6 specified, use only one",
              file=sys.stderr)
        sys.exit(1)

    if argi < len(sys.argv):
        client.host = sys.argv[argi]
        argi += 1
        client.port = int(sys.argv[argi])
        argi += 1

    client.c2s_key = binascii.unhexlify(config.get('keys', 'c2s'))
    client.s2c_key = binascii.unhexlify(config.get('keys', 's2c'))

    client.cookies = [ binascii.unhexlify(v) for k, v in sorted(config.items('cookies')) ]

    if not client.cookies:
        raise ValueError("no cookies in client.ini")

    # open communication to NTP server
    status = client.communicate()
    for s in client.infos:
        print("INFO: %s:%s: %s" % (client.host, client.port, s))
    for s in client.warnings:
        print("WARNING: %s:%s: %s" % (client.host, client.port, s))
    for s in client.errors:
        print("ERROR: %s:%s: %s" % (client.host, client.port, s))
    if client.errors:
        sys.exit(1)

    # update cookies in client.ini for next time
    if client.cookies:
        config.remove_section('cookies')
        config.add_section('cookies')
        for k, v in enumerate(client.cookies):
            config.set('cookies', str(k), binascii.hexlify(v).decode('ascii'))

        with open('client.ini', 'w') as f:
            config.write(f)

if __name__ == '__main__':
    main()
