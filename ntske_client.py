#! /usr/bin/python3
from __future__ import division, print_function, unicode_literals

import sys
import socket
import binascii
import struct
import util

from sslwrapper import SSLWrapper
from ntske_record import *
from nts import *

assert sys.version_info[0] == 3

NTS_ALPN_PROTO_B = NTS_ALPN_PROTO.encode('ASCII')

class NTSKEClient(object):
    def __init__(self):
        self.use_ke_legacy = False
        self.disable_verify = False
        self.ca = None
        self.verify_host = None
        self.strict = False
        self.ipv4_only = False
        self.ipv6_only = False
        self.debug = 0
        self.info = 0

    # setup SSL connection to KE server
    def communicate(self):
        wrapper = SSLWrapper()
        wrapper.enable_tlsv1_2()
        wrapper.client(self.ca, self.disable_verify)
        wrapper.set_alpn_protocols([NTS_ALPN_PROTO])

        try:
            if self.ipv4_only:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.host, self.port))
            elif self.ipv6_only:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.connect((self.host, self.port))
            else:
                sock = socket.create_connection((self.host, self.port))
        except ConnectionRefusedError as e:
            return e

        verify_host = self.verify_host
        if verify_host is None:
            verify_host = self.host

        try:
            s = wrapper.connect(sock, verify_host)
        except Exception as e:
            return e

        # set ALPN protocol to NTS_ALPN_PROTO = 'ntske/1'
        proto = s.selected_alpn_protocol()
        if proto != NTS_ALPN_PROTO:
            msg = "failed to negotiate ALPN proto, expected %s, got %s, continuing anyway" % (
                repr(NTS_ALPN_PROTO), repr(proto))
            if strict:
                raise IOError(msg)
            else:
                print("WARNING:", msg, file = sys.stderr)

        # allocate NTS Record structure
        records = []

        # 4.1.2. NTS Next Protocol Negotiation 
        npn_neg = Record()
        npn_neg.critical = True
        npn_neg.rec_type = RT_NEXT_PROTO_NEG
        npn_neg.body = struct.pack(">H", 1)
        records.append(npn_neg)

        aead_neg = Record()
        aead_neg.critical() = True
        aead_neg.rec_type = RT_ASSOCIATION_MODE
        aead_neg.body = pack(aead_neg.rec_type, 1)
        records.append(aead_neg)

        # 4.1.1. End of Message 
        eom = Record()
        eom.critical = True
        eom.rec_type = RT_END_OF_MESSAGE
        eom.body = b''
        records.append(eom)

        # send records to KE Server
        s.sendall(b''.join(map(bytes, records)))

        # set variables to receive
        npn_ack = False
        assoc_mode_ack = False

        eom = False

        do_shutdown = False

        while True:
            # receive response from KE server
            try:
                resp = s.recv(4)
            except socket.timeout:
                if eom:
                    print("timeout but EOM seen, continuing", file = sys.stderr)
                    break
                raise IOError("timeout but no EOM seen")

            # error checking
            if resp is None:
                if eom:
                    print("ragged EOF but EOM seen, continuing", file = sys.stderr)
                    break
                raise IOError("ragged EOF no EOM seen")

            elif not resp:
                if eom:
                    do_shutdown = True
                    break
                raise IOError("EOF but no EOM seen")

            if len(resp) < 4:
                raise IOError("short packet")

            body_len = struct.unpack(">H", resp[2:4])[0]
            if body_len > 0:
                resp += s.recv(body_len)
            record = Record(resp)
            if self.debug:
                print(record.critical, record.rec_type, repr(record.body), repr(resp))
            # received End of Message
            if record.rec_type == RT_END_OF_MESSAGE:
                eom = True
            elif record.rec_type == RT_ASSOCIATION_MODE:
                if RT_ASSOCIATION_MODE:
                    print("Duplicate association mode record", file=sys.stderr)
                    return 1
                if record.body != struct.pack(">H", 1):
                    print("Unacceptable association response", file=sys.stderr)
                    return 1
                RT_ASSOCIATION_MODE = True
            # received Next Protocol Negotiation acknowledgement
            elif record.rec_type == RT_NEXT_PROTO_NEG:
                if npn_ack:
                    print("Duplicate NPN record", file=sys.stderr)
                    return 1
                if record.body != struct.pack(">H", 1):
                    print("Unacceptable NPN response", file=sys.stderr)
                    return 1
                npn_ack = True
            # received error message
            elif record.rec_type == RT_ERROR:
                print("Received error response", file=sys.stderr)
                return 1
            # received something else
            else:
                if record.critical:
                    print("Unrecognized critical record", file=sys.stderr)
                    return 1

        # confirm we received Next Protocol Negotiation
        if not npn_ack:
            print("No NPN record in server response", file=sys.stderr)
            return 1
        # replaced code to mark assoc mode ack
        if not assoc_mode_ack:
            print("No association mode record in the server response", file=sts.stderr)
            return 1
        
        # export the cookies for client.ini
        key_label = NTS_TLS_Key_Label
        if self.use_ke_legacy:
            key_label = NTS_TLS_Key_Label_Legacy

        self.c2s_key = s.export_keying_material(key_label, NTS_TLS_Key_LEN, NTS_TLS_Key_C2S)
        self.s2c_key = s.export_keying_material(key_label, NTS_TLS_Key_LEN, NTS_TLS_Key_S2C)

        # shutdown if failed
        if do_shutdown:
            s.shutdown()

        # print to trace if debug is enabled
        if self.debug:
            print("C2S: " + binascii.hexlify(self.c2s_key).decode('utf-8'))
            print("S2C: " + binascii.hexlify(self.s2c_key).decode('utf-8'))
            

        if self.info:
            print("%s:%s -> %s:%s" % (self.host))

        return None

def main(argv):
    # setup NTS-KE Client
    client = NTSKEClient()

    # process command line arguments
    argi = 1

    while argv[argi].startswith('-'):
        opts = argv[argi][1:]
        argi += 1
        for o in opts:
            if o == 'k':
                client.use_ke_legacy = True
            elif o == 'v':
                client.disable_verify = True
            elif o == 'd':
                client.debug += 1
            elif o == 'i':
                client.info += 1
            elif o == 'c':
                client.ca = argv[argi]
                argi += 1
            elif o == 'h':
                client.verify_host = argv[argi]
                argi += 1
            elif o == 's':
                client.strict = True
            elif o == '4':
                client.ipv4_only = True
            elif o == '6':
                client.ipv6_only = True
            else:
                print("unknown option %s" % repr(o), file = sys.stderr)
                sys.exit(1)

    if argi + 2 != len(sys.argv):
        print("Usage: python [-kv] ntske_client.py <host> <port>",
              file = sys.stderr)
        sys.exit(1)

    if client.ipv4_only and client.ipv6_only:
        print("Error: both -4 and -6 specified, use only one",
              file=sys.stderr)
        sys.exit(1)

    client.host = argv[argi]
    argi += 1
    client.port = int(argv[argi])
    argi += 1

    # open NTS-KE session to KE Server
    e = client.communicate()
    if e:
        print("%s:%s: %s" % (client.host, client.port, e))
        sys.exit(1)

    # write config to client.ini for use by ntsts_client.py
    util.write_client_ini(client)

if __name__ == "__main__": # changed path to root Ca Bundle pem file
    if not sys.argv[0]:
        sys.argv = [ '', 'localhost', '4443', '...Cybersecurity-Capping-2023-NTS4PTP/rootCaBundle.pem']

    main(sys.argv)

