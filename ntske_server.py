#! /usr/bin/python3
from __future__ import division, print_function, unicode_literals


import os
import sys
import socket
import traceback
import binascii
import struct
import syslog
import signal
from socketserver import ThreadingTCPServer, TCPServer, BaseRequestHandler

from pooling import ThreadPoolTCPServer
from sslwrapper import SSLWrapper
from constants import *
from ntske_record import *
from nts import NTSCookie
from server_helper import ServerHelper
from util import hexlify
from threading import Timer

import logging

root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

assert sys.version_info[0] == 3

DEBUG = 0

ALLOW_MULTIPLE = 0

# Protocol IDs, see the IANA Network Time Security Next Protocols registry
SUPPORTED_PROTOCOLS = {
    0,                                  # NTPv4
    1,                                  # PTPv2.1
    }

# Algorithm identifiers, see RFC5297
SUPPORTED_ALGORITHMS = {
    0,                                 # Multicast Mode
    }

# unpack array from wire
def unpack_array(buf):
    assert(len(buf) % 2 == 0)
    fmt = '>%uH' % (len(buf) / 2)
    return struct.unpack(fmt, buf)

# pack array for wire
def pack_array(a):
    if len(a) == 0:
        return b''
    elif len(a) == 1:
        return struct.pack('>H', a[0])
    else:
        return struct.pack('>%uH' % len(a), fmt, a)
# will eventually be be flattened in the future, commenting out for now
# flatten multi-dimension list
# def flatten(a):
  #  return [ item for l in a for item in l ]

class NTSKEHandler(BaseRequestHandler):
    # handler for NTS KE Requests
    def handle(self):
        # fill info for handle2
        self.info = { 
            'site' : self.server.syslog,
            'client_addr' : self.client_address[0],
            'client_port' : self.client_address[1],
        }

        # run handle2 to actually handle the request
        try:
            status = self.handle2()
            if not isinstance(status, ''.__class__) or (
                    status != 'success' and not status.startswith('invalid')):
                status = 'invalid'
        except:
            status = 'exception'
            raise
        finally:
            self.info['status'] = status
            info = ' '.join([ '%s=%s' % (k,v) 
                              for k,v in sorted(self.info.items()) ])
            if 1:
                print(info)
            if self.server.syslog:
                syslog.syslog(syslog.LOG_INFO | syslog.LOG_USER, info)

    # receive request from client
    def recv_all(self, s, count):
        buf = bytes()
        while len(buf) < count:
            data = s.recv(count - len(buf))
            if not data:
                raise IOError("short recv")
            buf += data
        return buf

    # handle request from client
    def handle2(self):
        # print("Handle", self.client_address, "in child", os.getpid())

        # initialize structures in self
        self.keyid, self.key = self.server.helper.get_server_key()
        s = self.server.wrapper.accept(self.request)
        if not s:
            return 'invalid_tls_failure'

        if not self.server.helper.allow_any_alpn:
            alpn_protocol = s.selected_alpn_protocol()
            if alpn_protocol not in [NTS_ALPN_PROTO]:
                return('invalid_alpn_protocol')

        self.info.update(s.info())

        if DEBUG >= 2:
            print("keyid = unhexlify('''%s''')" % hexlify(self.keyid))
            print("server_key = unhexlify('''%s''')" % hexlify(self.key))

        self.npn_protocols = []
        self.assoction_modes = []
        assoc_mode_ack = False

        self.errors = set()
        npn_ack = False
        aead_ack = False
        protocols = []

        # run recv all to retrieve records from client
        while True:
            resp = self.recv_all(s, 4)
            if resp is None:
                return 'invalid_premature_eof'
                return 1
            if (len(resp) < 4):
                print("Premature end of client request", file = sys.stderr)
                return 'invalid_short_field'
            body_len = struct.unpack(">H", resp[2:4])[0]
            if body_len > 0:
                resp += self.recv_all(s, body_len)
            # process each record from client
            record = Record(resp)
            self.process_record(record)
            # end loop at EOM
            if record.rec_type == RT_END_OF_MESSAGE:
                break

    # print an error message
    def error(self, code, message):
        print("error %u: %s" % (code, message), file = sys.stderr)
        # add to self.errors so we know to send error record to client
        self.errors.add(code)
        if 0:
            raise ValueError(message)

    # print a notice message
    def notice(self, message):
        print(message, file = sys.stderr)

    # process records from client
    def process_record(self, record):
        if DEBUG >= 2:
            print(record.critical, record.rec_type, record.body)

        # something is wrong if called to process records from after the EOM
        if self.eom_received:
            self.error(ERR_BAD_REQUEST, "Records received after EOM")
            return

        # process an End of Message Record
        if record.rec_type == RT_END_OF_MESSAGE:
            # confirm message indicates critical
            if not record.critical:
                self.error(ERR_BAD_REQUEST,
                           "EOM record MUST be criticial")
                return

            # confirm zero length
            if len(record.body):
                self.error(ERR_BAD_REQUEST,
                           "EOM record should have zero length body")
                return

            self.eom_received = True

        # process 4.1.2. NTS Next Protocol Negotiation Record
        elif record.rec_type == RT_NEXT_PROTO_NEG:
            # confirm we are allowed to receive multiple NPN if we already received
            if self.npn_protocols:
                if ALLOW_MULTIPLE:
                    self.notice("Multiple NPN records")
                else:
                    self.error(ERR_BAD_REQUEST, "Multiple NPN record")
                    return

            # confirm critical is set
            if not record.critical:
                self.error(ERR_BAD_REQUEST, "NPN record MUST be criticial")
                return

            # confirm length is even
            if len(record.body) % 2:
                self.error(ERR_BAD_REQUEST,
                           "NPN record has invalid length")
                return

            # confirm length is non-zero
            if not len(record.body):
                self.error(ERR_BAD_REQUEST,
                           "NPN record MUST specify at least one protocol")

            # append the record body to self
            self.npn_protocols.append(unpack_array(record.body))
   
        #code to replace 4.1.5 AEAD Algorithm Negotiation Record
        else-if record.rec_type == RT_ASSOCIATION_MODE:
            if self.association_modes:
                if ALLOW_MULTIPLE:
                    self.notice("Multiple Association Mode records")
                else:
                    self.error(ERR_BAD_REQUEST, "Multiple Association Mode records")
                return 
                if record.body != 56:
                    self.error(ERR_BAD_REQUEST, "Association Mode record MUST not be empty")
                return
                self.association_modes.append(unpack_array(record.body))
            
        # process ERROR record
        elif record.rec_type == RT_ERROR:
            self.error(ERR_BAD_REQUEST, "Received error record")

        # process any other unknown records
        else:
            if record.critical:
                self.error(ERR_UNREC_CRIT, "Received unknown critical record %u" % (
                    record.rec_type))
            else:
                self.notice("Received unknown record %u" % (record.rec_type))

    # finish handling request and construct response to send to client
    def get_response(self):
        protocols = []
        # no NPN received
        if not self.npn_protocols:
            self.error(ERR_BAD_REQUEST, "No NPN record received")
        # unable to flatten received records
        elif not flatten(self.npn_protocols):
            pass
        # flatten NPN bodies into requested protocols
        else:
            for protocol in flatten(self.npn_protocols):
                if protocol in SUPPORTED_PROTOCOLS:
                    # append to list of protocols
                    protocols.append(protocol)
                else:
                    self.notice("Unknown NPN %u" % protocol)
            # no (supported) NPN received
            if not protocols:
                self.error(ERR_BAD_REQUEST, "No supported NPN received")
    # updated code
        modes = []
        if not self.association_modes:
            self.error(ERR_BAD_REQUEST, "No Association Modes record recieved")
        else:
            for modes in self.association_modes:
                DomainNumber = 0
                Sdold = 0
                SubGroup = 0
                modes.append(DomainNumber, Sdold, Subgroup)
            if not modes:
                self.error(ERR_BAD_REQUEST, "No Association Modes recieved")
        
            # client should have sent End of Message
        if not self.eom_received:
            self.error(ERR_BAD_REQUEST, "No EOM record received")

        # generate response records
        records = []

        # append ERROR record
        for code in sorted(self.errors):
            records.append(Record.make(True, RT_ERROR, struct.pack(">H", code)))

        # append NPN response/acknowledgment for first protocol received
        if protocols:
            records.append(Record.make(True, RT_NEXT_PROTO_NEG,
                                       struct.pack('>H', protocols[0])))
        # otherwise append empty NPN
        else:
            records.append(Record.make(True, RT_NEXT_PROTO_NEG,
                                       b''))

        # append End of Message if there were errors (no keys are sent in this case)
        if self.errors:
            records.append(Record.make(True, RT_END_OF_MESSAGE))
            return records
        
        # updated code
        for self.association_mode in modes:
            SecurityParameterPointer, KeyID, KeyLength, Key, Lifetime, UpdatePeriod, GracePeriod = accessDatabase(mode);
            SecurityParameterPointer = int.from_bytes(os.urandom(1), byteorder ="little")
            KeyID = int.from_bytes(os.urandom(4), byteorde r="little")
            
            if KeyID:
                KeyID = int.from_bytes(os.urandom(4), byteorder ="little")
            KeyLength = Key.length()
            Key = int.from_bytes(os.urandom(KeyLength), btyeorder = "big")
            Lifetime = int.from_bytes(os.urandom(4), byteorder="big")
            Lifetime_Countdown = 3600
            
            while Lifetime_Countdown > 0:
                os.urandom(1)
                Lifetime_Countdown -= 1
            UpdatePeriod = int.from_bytes(os.urandom(4), byteorder = "big")
            UpdatePeriod = 300
            GracePeriod = int.from_bytes(os.urandom(4), byteorder = "big")
            GracePeriod_Countdown = 5
            
            while GracePeriod_Countdown > 5:
                os.urandom(1)
                GracePeriod_Countdown -= 1
            paramter_list = list(SecurityParameterPointer, KeyID, KeyLength, Key, Lifetime, UpdatePeriod, GracePeriod)
            CurrentParameters = struct.pack(f"{len(parameter_list)}i", *parameter_list)
            records.append(Record.make(False, RT_CURRENT_PARAMETERS))
            
            if Lifetime < 300:
                SecurityParameterPointer, IntegrityAlgotithmTypes, KeyID, KeyLength, Key, Lifetime, UpdatePeriod, GracePeriod = accessDatabase(mode)
                SecurityParameterPointer = int.from_bytes(os.urandom(1), byteorder ="little")
                # need to fix to ask if already in use
                for SecurityParameterPointer:
                    if SecurityParameterPointer:
                        SecurityParameterPointer = int.from_bytes(os.urandom(1), byteorder ="little")
                    else:
                        return
                KeyID = int.from_bytes(os.urandom(4), byteorder ="little")
                if KeyID:
                    KeyID = int.from_bytes(os.urandom(4), byteorder ="little")
                Key = int.from_bytes(random(KeyLength))

        # append the End of Message Record
        records.append(Record.make(True, RT_END_OF_MESSAGE))

        return records

ChosenTCPServer = ThreadingTCPServer
ChosenTCPServer = ThreadPoolTCPServer

class NTSKEServer(ChosenTCPServer):
    allow_reuse_address = True

    address_family = socket.AF_INET6

    request_queue_size = 200

    #KE Server initialization - configure hosts/ports
    def __init__(self, config_path):
        self.helper = ServerHelper(config_path)

        host = ''
        port = int(self.helper.ntske_port)

        super(NTSKEServer, self).__init__((host, port), NTSKEHandler)

        self.ntpv4_server = self.helper.ntpv4_server
        self.ntpv4_port = self.helper.ntpv4_port
        self.key_label = self.helper.key_label
        self.syslog = self.helper.syslog

        if self.syslog:
            syslog.openlog('ntske-server')

    # run process indefinitely
    def serve_forever(self):
        self.refresh_wrapper()
        return super().serve_forever()

    # handle hangup call from parent thread
    def sighup(self, signalnumber, frame):
        print("pid %u received SIGHUP, refreshing" % os.getpid())
        self.refresh()

    # timer to refresh ssl wrapper every 60 seconds
    def refresh_wrapper(self):
        self.refresh()

        t = Timer(60, self.refresh_wrapper)
        t.daemon = True
        t.start()

    # refresh ssl wrapper
    def refresh(self):
        try:
            wrapper = SSLWrapper()
            if self.helper.allow_tlsv1_2:
                print("Enabling TLSv1.2")
                wrapper.enable_tlsv1_2()
            wrapper.server(self.helper.ntske_server_cert,
                           self.helper.ntske_server_key)
            wrapper.set_alpn_protocols([NTS_ALPN_PROTO])
            self.wrapper = wrapper
        except Exception:
            traceback.print_exc()

        try:
            self.helper.load_server_keys()
        except Exception:
            traceback.print_exc()

def run_mgmt(host, port, server_keys_dir, parent_pid):
    # Shut up flask about using test server 
    from flask import Flask
    cli = sys.modules['flask.cli']
    cli.show_server_banner = lambda *x: None

    import mgmt
    mgmt.server_keys_dir = server_keys_dir
    mgmt.parent_pid = parent_pid
    try:
        mgmt.application.run(host = host, port = port)
    except KeyboardInterrupt:
        pass
    print("mgmt", os.getpid(), "stopping...")

def main():
    # setup config path
    config_path = 'server.ini'

    if len(sys.argv) > 2:
        print("Usage: %s [server.ini]" % sys.argv[0], file = sys.stderr)
        sys.exit(1)

    if len(sys.argv) > 1:
        config_path = sys.argv[1]

    # initialize KE Server
    server = NTSKEServer(config_path)

    # setup helper threads - see server_helper.py
    pids = []

    print("master process", os.getpid())

    if 1:
        for i in range(server.helper.processes - 1):
            pid = os.fork()
            if pid == 0:
                print("child process", os.getpid())
                try:
                    try:
                        signal.signal(signal.SIGHUP, server.sighup)
                        server.serve_forever()
                    except KeyboardInterrupt:
                        pass
                    print("child", os.getpid(), "stopping...")
                    server.server_close()
                except:
                    import traceback
                    traceback.print_exc()
                finally:
                    sys.exit(0)
            else:
                pids.append(pid)

    # configure management process
    if server.helper.mgmt_host and server.helper.mgmt_port:
        print("starting mgmt web server on %s:%u"% (
            server.helper.mgmt_host,
            server.helper.mgmt_port))

        parent_pid = os.getpid()
        pid = os.fork()
        if pid == 0:
            print("mgmt process", os.getpid())
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            try:
                run_mgmt(server.helper.mgmt_host, server.helper.mgmt_port,
                         server.helper.server_keys_dir, parent_pid)
            except:
                import traceback
                traceback.print_exc()
            finally:
                sys.exit(0)
        else:
            pids.append(pid)

    # hangup helper threads
    def master_sighup(signalnumber, frame, server = server, pids = pids):
        server.sighup(signalnumber, frame)
        for pid in pids:
            os.kill(pid, signal.SIGHUP)

    try:
        signal.signal(signal.SIGHUP, master_sighup)
        server.serve_forever()
    except KeyboardInterrupt:
        print("keyboardinterrupt")

    print("shutting down...")

    # turn off server
    server.server_close()

    for pid in pids:
        p, status = os.wait()
        print("child", p, "has stopped")

if __name__ == "__main__":
    main()